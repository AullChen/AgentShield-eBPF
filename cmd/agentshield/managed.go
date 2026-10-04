package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/agentshield/agentshield-ebpf/internal/api"
	"github.com/agentshield/agentshield-ebpf/internal/bpfmgr"
	"github.com/agentshield/agentshield-ebpf/internal/config"
	"github.com/agentshield/agentshield-ebpf/internal/envcheck"
	"github.com/agentshield/agentshield-ebpf/internal/killer"
	"github.com/agentshield/agentshield-ebpf/internal/logging"
	"github.com/agentshield/agentshield-ebpf/internal/policy"
	"github.com/agentshield/agentshield-ebpf/internal/scope"
	"github.com/agentshield/agentshield-ebpf/internal/store"
	"github.com/agentshield/agentshield-ebpf/internal/stream"
)

type managedOptions struct {
	objectPath       string
	networkRoot      string
	managementSocket string
	ingestAddress    string
	readAddress      string
	tokenFile        string
	databasePath     string
	policyPath       string
}

func (options managedOptions) validate() error {
	if options.managementSocket == "" || options.databasePath == "" || options.tokenFile == "" || options.policyPath == "" || options.networkRoot == "" {
		return errors.New("serve requires --management-socket, --store, --read-token-file, --policy-file, and --cgroup-root")
	}
	if err := validateLoopbackListen(options.readAddress); err != nil {
		return err
	}
	if err := validateLoopbackListen(options.ingestAddress); err != nil {
		return err
	}
	if options.readAddress == options.ingestAddress {
		return errors.New("read API and checkpoint ingest require distinct listeners")
	}
	return nil
}

// managedRegistrar constrains registrations to the network attachment root
// and binds the one compiled block profile instead of accepting arbitrary IDs.
type managedRegistrar struct {
	*scope.Manager
	root    string
	profile uint32
}

func (registrar managedRegistrar) Register(ctx context.Context, target scope.Target, value scope.Value) (scope.Registration, error) {
	relative, err := filepath.Rel(registrar.root, filepath.Clean(target.Path))
	if err != nil || !filepath.IsAbs(target.Path) || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return scope.Registration{}, scope.ErrInvalidTarget
	}
	if value.ProfileID != 0 && value.ProfileID != registrar.profile {
		return scope.Registration{}, scope.ErrInvalidTarget
	}
	value.ProfileID = registrar.profile
	return registrar.Manager.Register(ctx, target, value)
}

func runManaged(cfg config.Config, options managedOptions) int {
	if err := options.validate(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	logger, err := logging.New(cfg.LogLevel)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := serveManaged(ctx, options, logger); err != nil {
		logger.Error("managed Core failed", slog.Any("error", err))
		return 1
	}
	return 0
}

func serveManaged(parent context.Context, options managedOptions, logger *slog.Logger) (resultErr error) {
	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	loaded, err := policy.LoadFile(options.policyPath, policy.Limits{})
	if err != nil {
		return err
	}
	// A single startup bank/profile cannot enforce different per-Run block
	// images. Audit/alert/contain retain all trusted scope types.
	for _, item := range loaded.Bundle.Policies {
		if item.Enabled && item.RequestedAction == policy.ActionBlock && item.Scope.Type != policy.ScopeGlobal {
			return errors.New("serve supports only global synchronous block policies")
		}
	}
	generation := policy.Generation{Revision: 1, Bank: policy.BankA}
	engine, _, err := policy.NewEngine(loaded.Bundle, generation, policy.Limits{})
	if err != nil {
		return err
	}
	image, err := policy.CompileNetworkEnforcement(loaded.Bundle, policy.EvaluationContext{}, 1, generation)
	if err != nil {
		return err
	}
	var enforcement *bpfmgr.NetworkEnforcementConfig
	if image != nil {
		enforcement = &bpfmgr.NetworkEnforcementConfig{ProfileID: image.ProfileID, Generation: image.Generation, PolicyID: image.PolicyID, RuleID: image.RuleID}
		for _, tuple := range image.Allows {
			enforcement.Allows = append(enforcement.Allows, bpfmgr.NetworkAllowTuple{AddressFamily: tuple.AddressFamily, Port: tuple.Port, Address: tuple.Address, MatchFlags: tuple.MatchFlags})
		}
	}
	resolver, err := scope.NewLinuxResolver("")
	if err != nil {
		return err
	}
	backend, err := killer.NewLinuxBackend("")
	if err != nil {
		return err
	}
	database, err := store.OpenSQLite(options.databasePath, store.SQLiteOptions{})
	if err != nil {
		return err
	}
	defer func() { resultErr = errors.Join(resultErr, database.Close()) }()
	token, err := loadReadToken(options.tokenFile)
	if err != nil {
		return err
	}
	redactor := store.NewRedactor([]string{token})
	writer, err := store.NewWriter(database, store.WriterOptions{Redactor: redactor, Diagnostics: os.Stderr})
	if err != nil {
		return err
	}
	defer func() {
		closeCtx, done := context.WithTimeout(context.Background(), 5*time.Second)
		defer done()
		resultErr = errors.Join(resultErr, writer.Close(closeCtx))
	}()
	hub, err := stream.NewHub(stream.HubOptions{})
	if err != nil {
		return err
	}
	defer hub.Close()
	overview := api.NewOverviewState(api.OverviewStateOptions{})
	diagnostics, err := api.NewDiagnosticsState(envcheck.Run(ctx), generation, api.DiagnosticsStateOptions{})
	if err != nil {
		return err
	}
	var manager *scope.Manager
	var registration *api.RegistrationHandler
	var pipeline *api.RuntimePipeline
	var servers []*http.Server
	serverFailures := make(chan error, 3)
	var monitorDone chan struct{}
	var shutdownOnce sync.Once
	var shutdownErr error
	shutdown := func() error {
		shutdownOnce.Do(func() {
			cancel()
			if monitorDone != nil {
				<-monitorDone
			}
			for _, server := range servers {
				closeCtx, done := context.WithTimeout(context.Background(), 5*time.Second)
				shutdownErr = errors.Join(shutdownErr, server.Shutdown(closeCtx))
				done()
			}
			if pipeline != nil {
				closeCtx, done := context.WithTimeout(context.Background(), 5*time.Second)
				shutdownErr = errors.Join(shutdownErr, pipeline.Close(closeCtx))
				done()
			}
			if manager != nil {
				for _, id := range manager.ActiveIDs() {
					shutdownErr = errors.Join(shutdownErr, manager.Unregister(id))
				}
			}
			select {
			case failure := <-serverFailures:
				shutdownErr = errors.Join(shutdownErr, failure)
			default:
			}
		})
		return shutdownErr
	}
	defer func() { resultErr = errors.Join(resultErr, shutdown()) }()
	start := func(listener net.Listener, routes http.Handler) {
		server := &http.Server{
			Handler:           routes,
			ReadHeaderTimeout: 5 * time.Second,
			ReadTimeout:       10 * time.Second,
			WriteTimeout:      10 * time.Second,
			IdleTimeout:       60 * time.Second,
			MaxHeaderBytes:    16 << 10,
		}
		servers = append(servers, server)
		go func() {
			if err := server.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
				serverFailures <- err
				cancel()
			}
		}()
	}
	report := func(err error) { logger.Warn("managed pipeline issue", slog.Any("error", err)) }
	return bpfmgr.RunAudit(ctx, bpfmgr.AuditOptions{
		OnStopping: shutdown,
		ObjectPath: options.objectPath, CgroupPath: options.networkRoot, NetworkEnforcement: enforcement,
		OnScopeMapReady: func(scopes bpfmgr.ScopeMap) error {
			manager, err = scope.NewManager(scopes, resolver, bpfmgr.LinuxScopeProbe{})
			if err != nil {
				return err
			}
			profile := uint32(0)
			if enforcement != nil {
				profile = enforcement.ProfileID
			}
			registration, err = api.NewRegistrationHandler(managedRegistrar{manager, filepath.Clean(options.networkRoot), profile}, api.NewRunStore(), api.RegistrationOptions{OnRunChanged: func(run api.AgentRun) {
				if pipeline != nil {
					pipeline.RunChanged(run)
				}
			}})
			if err != nil {
				return err
			}
			executor, err := killer.NewExecutor(manager, backend)
			if err != nil {
				return err
			}
			coordinator, err := api.NewPolicyCoordinator(registration.Store(), engine, executor)
			if err != nil {
				return err
			}
			pipeline, err = api.NewRuntimePipeline(api.RuntimePipelineOptions{Registration: registration, Coordinator: coordinator, Writer: writer, Hub: hub, Overview: overview, Redactor: redactor, OnError: report})
			return err
		},
		OnReady: func() {
			diagnostics.MarkHooksReady()
			checkpoint, err := api.NewCheckpointHandler(registration, api.CheckpointOptions{OnAccepted: pipeline.SubmitCheckpoint})
			if err != nil {
				serverFailures <- err
				cancel()
				return
			}
			readRoutes, err := managedReadRoutes(token, hub, overview, database, diagnostics, loaded.Bundle, generation, pipeline, writer)
			if err != nil {
				serverFailures <- err
				cancel()
				return
			}
			// Bind every surface before serving registration: a supervisor must
			// not release a workload while ingest/read startup can still fail.
			started := false
			management, err := api.ListenOwnerUnix(options.managementSocket)
			if err != nil {
				serverFailures <- err
				cancel()
				return
			}
			defer func() {
				if !started {
					_ = management.Close()
				}
			}()
			ingest, err := net.Listen("tcp", options.ingestAddress)
			if err != nil {
				serverFailures <- err
				cancel()
				return
			}
			defer func() {
				if !started {
					_ = ingest.Close()
				}
			}()
			readListener, err := net.Listen("tcp", options.readAddress)
			if err != nil {
				serverFailures <- err
				cancel()
				return
			}
			start(ingest, checkpoint.Routes())
			start(readListener, readRoutes)
			start(management, registration.Routes())
			started = true
			_ = overview.SetCapabilities([]api.OverviewCapability{{Name: "bpf_hooks", Status: "available", Detail: "all four hooks attached"}, {Name: "registered_runtime", Status: "available", Detail: "checkpoint, correlation, SQLite, and containment worker connected"}})
			monitorDone = make(chan struct{})
			go func() {
				defer close(monitorDone)
				ticker := time.NewTicker(time.Second)
				defer ticker.Stop()
				for {
					select {
					case <-ctx.Done():
						return
					case <-ticker.C:
						if err := api.MonitorScopesOnce(manager, scope.LinuxInspector{}, registration, time.Now(), func(event api.ScopeViolationEvent) error {
							logger.Warn("scope violation", slog.String("run_id", event.RunID), slog.String("reason", event.Reason))
							return nil
						}); err != nil {
							report(err)
						}
						if err := registration.CleanupExpiredRuns(); err != nil {
							report(err)
						}
					}
				}
			}()
			logger.Info("managed Core ready", slog.String("management_socket", options.managementSocket), slog.String("ingest", options.ingestAddress), slog.String("read_api", options.readAddress))
		},
		OnEvent: func(event bpfmgr.AuditEvent) error {
			if pipeline == nil {
				return errors.New("runtime pipeline unavailable")
			}
			return pipeline.SubmitKernel(event)
		},
		OnDropNotice: func(event bpfmgr.AuditEvent) {
			if err := diagnostics.ObserveDrop(event.DroppedEventTypeName, event.DroppedCount); err != nil {
				report(err)
			}
		},
		OnDerivedRecordError: report, OnMalformedEvent: report,
	}, os.Stdout)
}

func managedReadRoutes(token string, hub *stream.Hub, overview *api.OverviewState, database *store.SQLite, diagnostics *api.DiagnosticsState, bundle policy.Bundle, generation policy.Generation, pipeline *api.RuntimePipeline, writer *store.Writer) (http.Handler, error) {
	mux := http.NewServeMux()
	streamHandler, err := stream.NewHandler(hub, stream.HandlerOptions{ReadToken: token})
	if err != nil {
		return nil, err
	}
	mux.Handle("/api/v1/stream", streamHandler.Routes())
	mux.Handle("/api/v1/stream-ticket", streamHandler.Routes())
	overviewHandler, err := api.NewOverviewHandler(overview, api.OverviewHandlerOptions{ReadToken: token})
	if err != nil {
		return nil, err
	}
	mux.Handle("/api/v1/overview", overviewHandler.Routes())
	evidenceProvider, err := api.NewStoredEvidenceProvider(database)
	if err != nil {
		return nil, err
	}
	evidenceHandler, err := api.NewEvidenceHandler(evidenceProvider, api.EvidenceHandlerOptions{ReadToken: token})
	if err != nil {
		return nil, err
	}
	mux.Handle("/api/v1/evidence/", evidenceHandler.Routes())
	catalog, err := api.NewPolicyCatalog(&bundle, generation, api.PolicyCatalogOptions{})
	if err != nil {
		return nil, err
	}
	policyHandler, err := api.NewPolicyHandler(catalog, api.PolicyHandlerOptions{ReadToken: token})
	if err != nil {
		return nil, err
	}
	mux.Handle("/api/v1/policies", policyHandler.Routes())
	diagnosticHandler, err := api.NewDiagnosticsHandler(managedDiagnostics{diagnostics, pipeline, writer}, api.DiagnosticsHandlerOptions{ReadToken: token})
	if err != nil {
		return nil, err
	}
	mux.Handle("/api/v1/diagnostics", diagnosticHandler.Routes())
	return mux, nil
}

type managedDiagnostics struct {
	state    *api.DiagnosticsState
	pipeline *api.RuntimePipeline
	writer   *store.Writer
}

func (provider managedDiagnostics) Diagnostics(ctx context.Context) (api.DiagnosticsSnapshot, error) {
	result, err := provider.state.Diagnostics(ctx)
	if err != nil {
		return result, err
	}
	status := envcheck.StatusPass
	diagnostic := provider.writer.Diagnostics()
	if diagnostic.CircuitOpen || diagnostic.QueueDrops != 0 || diagnostic.StoreDrops != 0 || provider.pipeline.QueueDrops() != 0 {
		status = envcheck.StatusWarn
	}
	result.Checks = append(result.Checks, envcheck.Check{Name: "runtime_pipeline", Status: status, Message: "bounded runtime and durable evidence queues", Details: map[string]string{"pipeline_drops": fmt.Sprint(provider.pipeline.QueueDrops()), "store_queue_drops": fmt.Sprint(diagnostic.QueueDrops), "store_drops": fmt.Sprint(diagnostic.StoreDrops), "store_circuit_open": fmt.Sprint(diagnostic.CircuitOpen)}})
	return result, nil
}
