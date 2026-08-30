package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/agentshield/agentshield-ebpf/internal/evidence"
	"github.com/agentshield/agentshield-ebpf/internal/stream"
)

const evidenceReadToken = "evidence-read-token-123456789"

func TestStreamEvidenceProviderPreservesSourceBoundaries(t *testing.T) {
	hub, err := stream.NewHub(stream.HubOptions{})
	if err != nil {
		t.Fatal(err)
	}
	publishEvidenceTestEvent(t, hub, stream.Event{
		ID: "kernel-1", Type: "kernel_event", Source: "kernel_fact", RunID: "run-1", EventType: "exec_attempt",
		ServerMonotonicNS: 10, ServerUnixNS: 20,
		Payload: json.RawMessage(`{"event_type_name":"exec_attempt","action_result_name":"none","data":"/bin/sh"}`),
	})
	publishEvidenceTestEvent(t, hub, stream.Event{
		ID: "diag-1", Type: "drop_notice", Source: "diagnostic", RunID: "run-1", EventType: "drop_notice",
		ServerMonotonicNS: 11, ServerUnixNS: 21, Payload: json.RawMessage(`{"dropped_count":"2"}`),
	})
	publishEvidenceTestEvent(t, hub, stream.Event{
		ID: "decision-1", Type: "policy_decision", Source: "policy_decision", RunID: "run-1", EventType: "policy_decision",
		ServerMonotonicNS: 12, ServerUnixNS: 22,
		Payload: json.RawMessage(`{"event_type_name":"exec_attempt","final":{"policy_id":"deny-shell","rule_id":7,"policy_decision":"deny","requested_action":"contain","enforced":false}}`),
	})
	publishEvidenceTestEvent(t, hub, stream.Event{
		ID: "containment-1", Type: "containment_result", Source: "containment_result", RunID: "run-1", EventType: "containment_result",
		ServerMonotonicNS: 13, ServerUnixNS: 23,
		Payload: json.RawMessage(`{"requested_action":"contain","enforcement_result":"killed","enforcement_method":"cgroup_kill","cgroup_id":"42","instance_id":"1001","scope_cookie":"2002","syscall_result":"not_observed"}`),
	})
	provider, err := NewStreamEvidenceProvider(hub)
	if err != nil {
		t.Fatal(err)
	}
	timeline, err := provider.Evidence(t.Context(), "run-1")
	if err != nil {
		t.Fatal(err)
	}
	if len(timeline.Items) != 3 {
		t.Fatalf("items = %#v", timeline.Items)
	}
	kernel := timeline.Items[0]
	if kernel.Source != evidence.KernelFact || kernel.Operation == nil || !kernel.Operation.AttemptObserved ||
		kernel.Operation.ActionResult != "none" || kernel.Attribution != nil || kernel.Correlation != nil {
		t.Fatalf("kernel evidence = %#v", kernel)
	}
	decision := timeline.Items[1]
	if decision.Source != evidence.PolicyDecision || decision.Decision == nil || decision.Decision.PolicyID != "deny-shell" ||
		decision.Decision.Enforced || decision.Decision.Mechanism != "post_event evaluation" {
		t.Fatalf("policy evidence = %#v", decision)
	}
	containment := timeline.Items[2]
	if containment.Source != evidence.ContainmentResult || containment.Containment == nil ||
		!containment.Containment.Requested || containment.Containment.Result != "killed" ||
		containment.Containment.Method != "cgroup_kill" || containment.Containment.OriginalActionResult != "not_observed" ||
		containment.Containment.TargetIdentity != "cgroup_id=42,instance_id=1001,scope_cookie=2002" {
		t.Fatalf("containment evidence = %#v", containment)
	}
}

func TestStreamEvidenceProviderAcceptsRepeatedSourceRecords(t *testing.T) {
	hub, err := stream.NewHub(stream.HubOptions{})
	if err != nil {
		t.Fatal(err)
	}
	event := stream.Event{
		ID: "kernel-repeated", Type: "kernel_event", Source: "kernel_fact", RunID: "run-1", EventType: "exec_attempt",
		ServerMonotonicNS: 10, ServerUnixNS: 20,
		Payload: json.RawMessage(`{"event_type_name":"exec_attempt","action_result_name":"none","data":"/bin/sh"}`),
	}
	publishEvidenceTestEvent(t, hub, event)
	publishEvidenceTestEvent(t, hub, event)
	provider, err := NewStreamEvidenceProvider(hub)
	if err != nil {
		t.Fatal(err)
	}
	timeline, err := provider.Evidence(t.Context(), "run-1")
	if err != nil {
		t.Fatal(err)
	}
	if len(timeline.Items) != 2 || timeline.Items[0].ID == timeline.Items[1].ID {
		t.Fatalf("repeated record projection = %#v", timeline.Items)
	}
}

func TestEvidenceHandlerRequiresTokenAndReturnsRun(t *testing.T) {
	timeline, err := evidence.Build("run-1", nil)
	if err != nil {
		t.Fatal(err)
	}
	handler, err := NewEvidenceHandler(staticEvidenceProvider{timeline: timeline}, EvidenceHandlerOptions{ReadToken: evidenceReadToken})
	if err != nil {
		t.Fatal(err)
	}
	unauthorized := httptest.NewRecorder()
	handler.Routes().ServeHTTP(unauthorized, httptest.NewRequest(http.MethodGet, "/api/v1/evidence/run-1", nil))
	if unauthorized.Code != http.StatusUnauthorized {
		t.Fatalf("unauthorized status = %d", unauthorized.Code)
	}
	request := httptest.NewRequest(http.MethodGet, "/api/v1/evidence/run-1", nil)
	request.Header.Set("Authorization", "Bearer "+evidenceReadToken)
	response := httptest.NewRecorder()
	handler.Routes().ServeHTTP(response, request)
	if response.Code != http.StatusOK || response.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("response status = %d, cache = %q", response.Code, response.Header().Get("Cache-Control"))
	}
	var got evidence.Timeline
	if err := json.NewDecoder(response.Body).Decode(&got); err != nil {
		t.Fatal(err)
	}
	if got.RunID != "run-1" || got.SchemaVersion != evidence.SchemaVersion {
		t.Fatalf("timeline = %#v", got)
	}
}

func publishEvidenceTestEvent(t *testing.T, hub *stream.Hub, event stream.Event) {
	t.Helper()
	if _, err := hub.Publish(event); err != nil {
		t.Fatal(err)
	}
}

type staticEvidenceProvider struct {
	timeline evidence.Timeline
}

func (provider staticEvidenceProvider) Evidence(_ context.Context, _ string) (evidence.Timeline, error) {
	return provider.timeline, nil
}
