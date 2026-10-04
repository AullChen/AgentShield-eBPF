package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/agentshield/agentshield-ebpf/internal/api"
	"github.com/agentshield/agentshield-ebpf/internal/envcheck"
	"github.com/agentshield/agentshield-ebpf/internal/evidence"
	"github.com/agentshield/agentshield-ebpf/internal/policy"
	"github.com/agentshield/agentshield-ebpf/internal/stream"
)

const fixtureRunID = "run-demo"

type fixture struct {
	handler http.Handler
	hub     *stream.Hub
}

type staticEvidence struct {
	timeline evidence.Timeline
}

func (provider staticEvidence) Evidence(_ context.Context, runID string) (evidence.Timeline, error) {
	if runID != provider.timeline.RunID {
		return evidence.Build(runID, nil)
	}
	return provider.timeline, nil
}

func main() {
	listen := flag.String("listen", "127.0.0.1:18080", "loopback IP:port for the acceptance fixture")
	policyFile := flag.String("policy-file", "configs/default-policies.yaml", "validated policy bundle shown by the fixture")
	flag.Parse()
	if err := run(*listen, *policyFile); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(address, policyFile string) error {
	token := os.Getenv("AGENTSHIELD_READ_TOKEN")
	if len(token) < 24 || len(token) > 512 || strings.ContainsAny(token, " \t\r\n") {
		return errors.New("AGENTSHIELD_READ_TOKEN must contain 24-512 non-whitespace bytes")
	}
	if err := requireLoopback(address); err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	fixture, err := newFixture(ctx, token, policyFile)
	if err != nil {
		return err
	}
	listener, err := net.Listen("tcp", address)
	if err != nil {
		return fmt.Errorf("listen for dashboard acceptance fixture: %w", err)
	}
	server := &http.Server{Handler: fixture.handler, ReadHeaderTimeout: 5 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 16 << 10}
	failure := make(chan error, 1)
	go func() {
		if err := server.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
			failure <- err
		}
	}()
	go replay(ctx, fixture.hub)
	fmt.Printf("dashboard acceptance fixture listening on %s (deterministic replay; not kernel proof)\n", listener.Addr())
	select {
	case <-ctx.Done():
	case err := <-failure:
		return fmt.Errorf("serve dashboard acceptance fixture: %w", err)
	}
	fixture.hub.Close()
	shutdownContext, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return server.Shutdown(shutdownContext)
}

func newFixture(ctx context.Context, token, policyFile string) (*fixture, error) {
	loaded, err := policy.LoadFile(policyFile, policy.Limits{})
	if err != nil {
		return nil, fmt.Errorf("load fixture policies: %w", err)
	}
	generation := policy.Generation{Revision: 1, Bank: policy.BankA}
	timeline, err := evidence.BuildSampleTimeline()
	if err != nil {
		return nil, err
	}
	hub, err := stream.NewHub(stream.HubOptions{})
	if err != nil {
		return nil, err
	}
	streamHandler, err := stream.NewHandler(hub, stream.HandlerOptions{ReadToken: token})
	if err != nil {
		return nil, err
	}
	overview := api.NewOverviewState(api.OverviewStateOptions{})
	if err := overview.UpsertRun(api.OverviewRunInput{RunID: fixtureRunID, Label: "Dashboard acceptance fixture", Status: "active", StartedAt: time.Now().Add(-2 * time.Minute)}); err != nil {
		return nil, err
	}
	if err := overview.ObserveEvent(api.OverviewEventInput{RunID: fixtureRunID, Blocked: false}); err != nil {
		return nil, err
	}
	if err := overview.ObserveEvent(api.OverviewEventInput{RunID: fixtureRunID, Blocked: true}); err != nil {
		return nil, err
	}
	if err := overview.ObservePolicyHit(fixtureRunID); err != nil {
		return nil, err
	}
	if err := overview.ObservePolicyHit(fixtureRunID); err != nil {
		return nil, err
	}
	if err := overview.SetCapabilities([]api.OverviewCapability{
		{Name: "acceptance_fixture", Status: "degraded", Detail: "deterministic evidence replay; synthetic kernel records"},
		{Name: "bpf_hooks", Status: "unknown", Detail: "fixture does not perform privileged load or attach"},
		{Name: "kernel_network_enforcement_connect6", Status: "unavailable", Detail: "fixture://kernel-network-enforcement/ipv6/no-real-kernel-claim"},
		{Name: "realtime_api", Status: "available", Detail: "authenticated ticket and WebSocket replay active"},
	}); err != nil {
		return nil, err
	}
	overviewHandler, err := api.NewOverviewHandler(overview, api.OverviewHandlerOptions{ReadToken: token})
	if err != nil {
		return nil, err
	}
	evidenceHandler, err := api.NewEvidenceHandler(staticEvidence{timeline: timeline}, api.EvidenceHandlerOptions{ReadToken: token})
	if err != nil {
		return nil, err
	}
	catalog, err := api.NewPolicyCatalog(&loaded.Bundle, generation, api.PolicyCatalogOptions{})
	if err != nil {
		return nil, err
	}
	policyHandler, err := api.NewPolicyHandler(catalog, api.PolicyHandlerOptions{ReadToken: token})
	if err != nil {
		return nil, err
	}
	report := envcheck.Run(ctx)
	report.Checks = append(report.Checks, envcheck.Check{Name: "acceptance_fixture", Status: envcheck.StatusWarn, Message: "deterministic dashboard replay is active; no kernel claim is made"})
	diagnostics, err := api.NewDiagnosticsState(report, generation, api.DiagnosticsStateOptions{})
	if err != nil {
		return nil, err
	}
	diagnosticsHandler, err := api.NewDiagnosticsHandler(diagnostics, api.DiagnosticsHandlerOptions{ReadToken: token})
	if err != nil {
		return nil, err
	}
	routes := http.NewServeMux()
	routes.Handle("/api/v1/overview", overviewHandler.Routes())
	routes.Handle("/api/v1/evidence/", evidenceHandler.Routes())
	routes.Handle("/api/v1/policies", policyHandler.Routes())
	routes.Handle("/api/v1/diagnostics", diagnosticsHandler.Routes())
	routes.Handle("/api/v1/stream", streamHandler.Routes())
	routes.Handle("/api/v1/stream-ticket", streamHandler.Routes())
	routes.HandleFunc("GET /healthz", func(response http.ResponseWriter, _ *http.Request) { response.WriteHeader(http.StatusNoContent) })
	return &fixture{handler: routes, hub: hub}, nil
}

type replayEvent struct {
	typeName string
	source   string
	severity string
	audit    bool
	payload  string
}

func replay(ctx context.Context, hub *stream.Hub) {
	events := []replayEvent{
		{typeName: "agent_checkpoint", source: "agent_claim", severity: "info", payload: `{"summary":"Agent declared a shell tool start","checkpoint_id":"checkpoint-tool-1"}`},
		{typeName: "exec_attempt", source: "kernel_fact", severity: "medium", audit: true, payload: `{"summary":"exec attempt observed; completion is unknown","action_result_name":"none","data":"/bin/sh","cgroup_id":"4242"}`},
		{typeName: "policy_decision", source: "policy_decision", severity: "high", payload: `{"summary":"deny and request post-event containment","event_type_name":"exec_attempt","final":{"policy_id":"policy-exec","rule_id":1,"policy_decision":"deny","requested_action":"contain","enforced":false}}`},
		{typeName: "containment_result", source: "containment_result", severity: "high", payload: `{"summary":"exact fixture scope containment reported","requested_action":"contain","enforcement_result":"killed","enforcement_method":"cgroup_kill","cgroup_id":"42","instance_id":"9007199254740993","scope_cookie":"9007199254740994","syscall_result":"not_observed"}`},
		{typeName: "net_connect", source: "kernel_fact", severity: "high", audit: true, payload: `{"summary":"network connection attempt blocked by hook","action_result_name":"blocked","dst_ip":"203.0.113.10","dst_port":443,"cgroup_id":"4242"}`},
		{typeName: "policy_decision", source: "policy_decision", severity: "high", payload: `{"summary":"synchronous network block","event_type_name":"net_connect","final":{"policy_id":"policy-network","rule_id":1,"policy_decision":"deny","requested_action":"block","enforced":true}}`},
	}
	ticker := time.NewTicker(450 * time.Millisecond)
	defer ticker.Stop()
	started := time.Now()
	sequence := uint64(0)
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-ticker.C:
			template := events[sequence%uint64(len(events))]
			sequence++
			payload := []byte(template.payload)
			if _, err := hub.Publish(stream.Event{
				ID: "fixture-" + strconv.FormatUint(sequence, 10), Type: template.typeName,
				Source: template.source, RunID: fixtureRunID, Severity: template.severity, EventType: template.typeName,
				ServerMonotonicNS: uint64(time.Since(started).Nanoseconds()) + 1, ServerUnixNS: uint64(now.UnixNano()),
				Audit: template.audit, Payload: payload,
			}); err != nil {
				return
			}
		}
	}
}

func requireLoopback(address string) error {
	host, port, err := net.SplitHostPort(address)
	if err != nil || port == "" {
		return errors.New("--listen must be an IP:port address")
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		return errors.New("dashboard acceptance fixture may listen only on a loopback IP")
	}
	return nil
}
