// sandbox-init is a trusted, statically linked PID 1, not an Agent entrypoint.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"
	"time"
)

const gatewaySocket = "/run/agentshield/gateway.sock"
const relayAddress = "127.0.0.1:18181"

type launchRequest struct {
	RunID       string            `json:"run_id"`
	IngestToken string            `json:"ingest_token"`
	Command     []string          `json:"command"`
	Environment map[string]string `json:"environment"`
	Timeout     int               `json:"timeout_seconds"`
}

func main() {
	if err := prepare(); err != nil {
		fmt.Fprintln(os.Stderr, "trusted sandbox preparation failed")
		os.Exit(125)
	}
	code, err := launch(os.Stdin)
	if err != nil {
		fmt.Fprintln(os.Stderr, "trusted sandbox launch failed")
		os.Exit(125)
	}
	os.Exit(code)
}

func launch(input io.Reader) (int, error) {
	request, err := decodeLaunch(input)
	if err != nil {
		return 125, err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	ctx, cancel := context.WithTimeout(ctx, time.Duration(request.Timeout)*time.Second)
	defer cancel()
	listener, err := net.Listen("tcp4", relayAddress)
	if err != nil {
		return 125, err
	}
	transport := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, "unix", gatewaySocket)
		},
		MaxConnsPerHost: 4, MaxIdleConnsPerHost: 4,
		ResponseHeaderTimeout: 15 * time.Second, DisableCompression: true,
	}
	defer transport.CloseIdleConnections()
	server := &http.Server{Handler: relayHandler(request, transport), ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout: 10 * time.Second, WriteTimeout: 60 * time.Second, MaxHeaderBytes: 16 << 10}
	go func() {
		if err := server.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
			cancel()
		}
	}()
	defer server.Close()
	command := exec.CommandContext(ctx, request.Command[0], request.Command[1:]...)
	command.Dir = "/workspace"
	command.Env = environment(request)
	// Only new stdio streams are inherited. No ExtraFiles, old sockets, or
	// supervisor management credentials are handed to the workload.
	command.Stdout, command.Stderr = os.Stdout, os.Stderr
	configureProcess(command)
	if err := command.Run(); err != nil {
		var exit *exec.ExitError
		if errors.As(err, &exit) {
			return exit.ExitCode(), nil
		}
		return 125, errors.New("workload failed")
	}
	return 0, nil
}

func decodeLaunch(input io.Reader) (launchRequest, error) {
	data, err := io.ReadAll(io.LimitReader(input, (16<<10)+1))
	if err != nil || len(data) > 16<<10 {
		return launchRequest{}, errors.New("invalid launch envelope")
	}
	var request launchRequest
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&request); err != nil {
		return launchRequest{}, errors.New("invalid launch envelope")
	}
	var extra any
	if decoder.Decode(&extra) != io.EOF || len(request.RunID) != 32 || len(request.IngestToken) == 0 || len(request.IngestToken) > 512 ||
		len(request.Command) == 0 || len(request.Command) > 64 || !strings.HasPrefix(request.Command[0], "/") || request.Timeout < 1 || request.Timeout > 900 {
		return launchRequest{}, errors.New("invalid launch envelope")
	}
	for _, character := range request.RunID {
		if !(character >= '0' && character <= '9' || character >= 'a' && character <= 'f') {
			return launchRequest{}, errors.New("invalid Run identity")
		}
	}
	for _, argument := range request.Command {
		if len(argument) > 4096 || strings.ContainsRune(argument, 0) {
			return launchRequest{}, errors.New("invalid workload command")
		}
	}
	for key, value := range request.Environment {
		switch key {
		case "LANG", "TZ", "TERM", "MODEL_NAME":
		default:
			return launchRequest{}, errors.New("environment variable is not approved")
		}
		if len(value) > 256 || strings.ContainsRune(value, 0) {
			return launchRequest{}, errors.New("invalid environment value")
		}
	}
	return request, nil
}

func environment(request launchRequest) []string {
	result := []string{"PATH=/usr/local/bin:/usr/bin:/bin", "HOME=/tmp",
		"AGENTSHIELD_RUN_ID=" + request.RunID, "AGENTSHIELD_INGEST_TOKEN=" + request.IngestToken,
		"AGENTSHIELD_INGEST_URL=http://" + relayAddress, "AGENTSHIELD_GATEWAY_URL=http://" + relayAddress}
	if _, ok := request.Environment["LANG"]; !ok {
		result = append(result, "LANG=C")
	}
	for key, value := range request.Environment {
		result = append(result, key+"="+value)
	}
	return result
}

func relayHandler(credentials launchRequest, transport http.RoundTripper) http.Handler {
	return http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodPost || request.URL.RawQuery != "" || request.URL.RawPath != "" || request.Header.Get("Origin") != "" {
			http.Error(response, "unsupported gateway request", http.StatusForbidden)
			return
		}
		if !strings.HasPrefix(request.URL.Path, "/gateway/v1/") &&
			request.URL.Path != "/ingest/v1/runs/"+credentials.RunID+"/checkpoints" {
			http.Error(response, "route unavailable", http.StatusNotFound)
			return
		}
		out := request.Clone(request.Context())
		out.URL.Scheme, out.URL.Host, out.Host, out.RequestURI = "http", "localhost", "localhost", ""
		out.Header = make(http.Header)
		for _, name := range []string{"Content-Type", "Accept", "MCP-Protocol-Version"} {
			out.Header.Set(name, request.Header.Get(name))
		}
		out.Header.Set("Authorization", "Bearer "+credentials.IngestToken)
		out.Body = http.MaxBytesReader(response, request.Body, 256<<10)
		upstream, err := transport.RoundTrip(out)
		if err != nil {
			http.Error(response, "gateway unavailable", http.StatusServiceUnavailable)
			return
		}
		defer upstream.Body.Close()
		for _, name := range []string{"Content-Type", "Cache-Control"} {
			response.Header().Set(name, upstream.Header.Get(name))
		}
		response.WriteHeader(upstream.StatusCode)
		_, _ = io.Copy(response, io.LimitReader(upstream.Body, 8<<20))
	})
}
