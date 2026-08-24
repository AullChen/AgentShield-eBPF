package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/agentshield/agentshield-ebpf/internal/api"
	streamapi "github.com/agentshield/agentshield-ebpf/internal/stream"
)

type liveAPIOptions struct {
	listenAddress string
	readTokenFile string
	runID         string
}

func (options liveAPIOptions) enabled() bool {
	return options.listenAddress != "" || options.readTokenFile != "" || options.runID != ""
}

type liveAPI struct {
	server    *http.Server
	address   string
	hub       *streamapi.Hub
	sink      io.Writer
	state     *api.OverviewState
	runID     string
	startedAt time.Time
	failure   chan error
}

func startLiveAPI(ctx context.Context, cancel context.CancelFunc, options liveAPIOptions, logger *slog.Logger) (*liveAPI, error) {
	if options.listenAddress == "" || options.readTokenFile == "" || options.runID == "" {
		return nil, errors.New("--api-listen, --read-token-file, and --run-id must be supplied together")
	}
	if len(options.runID) > 128 {
		return nil, errors.New("live API Run ID is invalid")
	}
	if err := validateLoopbackListen(options.listenAddress); err != nil {
		return nil, err
	}
	readToken, err := loadReadToken(options.readTokenFile)
	if err != nil {
		return nil, err
	}

	hub, err := streamapi.NewHub(streamapi.HubOptions{})
	if err != nil {
		return nil, err
	}
	streamHandler, err := streamapi.NewHandler(hub, streamapi.HandlerOptions{ReadToken: readToken})
	if err != nil {
		return nil, err
	}
	state := api.NewOverviewState(api.OverviewStateOptions{})
	startedAt := time.Now()
	if err := state.UpsertRun(api.OverviewRunInput{RunID: options.runID, Label: options.runID, Status: "active", StartedAt: startedAt}); err != nil {
		return nil, err
	}
	if err := state.SetCapabilities([]api.OverviewCapability{
		{Name: "bpf_hooks", Status: "unknown", Detail: "waiting for load and attach"},
		{Name: "cgroup_v2", Status: "available", Detail: "trusted exact leaf resolved"},
		{Name: "realtime_api", Status: "available", Detail: "bounded WebSocket fan-out active"},
	}); err != nil {
		return nil, err
	}
	overviewHandler, err := api.NewOverviewHandler(state, api.OverviewHandlerOptions{ReadToken: readToken})
	if err != nil {
		return nil, err
	}
	sink, err := streamapi.NewJSONLineSink(hub, streamapi.JSONLineSinkOptions{
		RunID: options.runID, SensitiveValues: []string{readToken},
		OnPublished: func(record streamapi.PublishedRecord) {
			if record.KernelFact {
				if err := state.ObserveEvent(api.OverviewEventInput{RunID: record.RunID, Blocked: record.Blocked}); err != nil {
					logger.WarnContext(ctx, "overview event update failed", slog.Any("error", err))
				}
			}
			if record.PolicyDecision {
				if err := state.ObservePolicyHit(record.RunID); err != nil {
					logger.WarnContext(ctx, "overview policy update failed", slog.Any("error", err))
				}
			}
		},
		OnError: func(err error) {
			logger.WarnContext(ctx, "realtime record dropped", slog.Any("error", err))
		},
	})
	if err != nil {
		return nil, err
	}

	routes := http.NewServeMux()
	routes.Handle("/api/v1/overview", overviewHandler.Routes())
	routes.Handle("/api/v1/stream", streamHandler.Routes())
	routes.Handle("/api/v1/stream-ticket", streamHandler.Routes())
	listener, err := net.Listen("tcp", options.listenAddress)
	if err != nil {
		return nil, fmt.Errorf("listen for dashboard API: %w", err)
	}
	live := &liveAPI{
		server: &http.Server{
			Handler: routes, ReadHeaderTimeout: 5 * time.Second, IdleTimeout: 60 * time.Second,
			MaxHeaderBytes: 16 << 10,
		},
		address: listener.Addr().String(), hub: hub, sink: sink, state: state, runID: options.runID,
		startedAt: startedAt, failure: make(chan error, 1),
	}
	go func() {
		if err := live.server.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
			live.failure <- err
			cancel()
		}
	}()
	return live, nil
}

func (live *liveAPI) output(standard io.Writer) io.Writer {
	return io.MultiWriter(standard, live.sink)
}

func (live *liveAPI) hooksReady() {
	_ = live.state.SetCapabilities([]api.OverviewCapability{
		{Name: "bpf_hooks", Status: "available", Detail: "audit hooks loaded and attached"},
		{Name: "cgroup_v2", Status: "available", Detail: "trusted exact leaf resolved"},
		{Name: "realtime_api", Status: "available", Detail: "bounded WebSocket fan-out active"},
	})
}

func (live *liveAPI) close(status string) error {
	_ = live.state.UpsertRun(api.OverviewRunInput{
		RunID: live.runID, Label: live.runID, Status: status, StartedAt: live.startedAt,
	})
	live.hub.Close()
	shutdownContext, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	shutdownErr := live.server.Shutdown(shutdownContext)
	select {
	case serveErr := <-live.failure:
		return errors.Join(shutdownErr, fmt.Errorf("dashboard API failed: %w", serveErr))
	default:
		return shutdownErr
	}
}

func validateLoopbackListen(address string) error {
	host, port, err := net.SplitHostPort(address)
	if err != nil || port == "" {
		return errors.New("--api-listen must be an IP:port address")
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		return errors.New("plain HTTP dashboard API may listen only on a loopback IP")
	}
	return nil
}

func loadReadToken(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("open read token file: %w", err)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return "", fmt.Errorf("stat read token file: %w", err)
	}
	if !info.Mode().IsRegular() {
		return "", errors.New("read token file must be a regular file")
	}
	if runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0 {
		return "", errors.New("read token file must not be accessible by group or other users")
	}
	contents, err := io.ReadAll(io.LimitReader(file, 514))
	if err != nil {
		return "", fmt.Errorf("read token file: %w", err)
	}
	token := strings.TrimSpace(string(contents))
	if len(token) < 24 || len(token) > 512 || strings.ContainsAny(token, " \t\r\n") {
		return "", errors.New("read token file contains an invalid token")
	}
	return token, nil
}
