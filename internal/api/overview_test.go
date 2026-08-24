package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

const overviewReadToken = "overview-read-token-123456789"

func TestOverviewStateUsesStringCountsAndRealRunData(t *testing.T) {
	now := time.Date(2026, 8, 21, 2, 0, 0, 0, time.UTC)
	state := NewOverviewState(OverviewStateOptions{Now: func() time.Time { return now }})
	if err := state.UpsertRun(OverviewRunInput{RunID: "run-1", Label: "demo", Status: "active", StartedAt: now.Add(-time.Minute)}); err != nil {
		t.Fatal(err)
	}
	if err := state.ObserveEvent(OverviewEventInput{RunID: "run-1", PolicyHit: true, Blocked: true, OccurredAt: now}); err != nil {
		t.Fatal(err)
	}
	if err := state.ObservePolicyHit("run-1"); err != nil {
		t.Fatal(err)
	}
	if err := state.SetCapabilities([]OverviewCapability{
		{Name: "cgroup_v2", Status: "available", Detail: "exact leaf registered"},
		{Name: "bpf_load", Status: "unknown", Detail: "active probe pending"},
	}); err != nil {
		t.Fatal(err)
	}

	snapshot, err := state.Overview(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.Counts.ActiveRuns != "1" || snapshot.Counts.KernelEvents != "1" ||
		snapshot.Counts.PolicyHits != "2" || snapshot.Counts.Blocked != "1" {
		t.Fatalf("counts = %#v", snapshot.Counts)
	}
	if len(snapshot.Runs) != 1 || snapshot.Runs[0].RunID != "run-1" ||
		snapshot.Runs[0].EventCount != "1" || snapshot.Runs[0].BlockedCount != "1" {
		t.Fatalf("runs = %#v", snapshot.Runs)
	}
	if snapshot.Capabilities[0].Name != "bpf_load" {
		t.Fatalf("capabilities are not deterministic: %#v", snapshot.Capabilities)
	}
	encoded, err := json.Marshal(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	var wire map[string]any
	if err := json.Unmarshal(encoded, &wire); err != nil {
		t.Fatal(err)
	}
	counts := wire["counts"].(map[string]any)
	if _, ok := counts["kernel_events"].(string); !ok {
		t.Fatalf("kernel_events wire type = %T, want string", counts["kernel_events"])
	}
}

func TestOverviewHandlerRequiresReadToken(t *testing.T) {
	state := NewOverviewState(OverviewStateOptions{})
	handler, err := NewOverviewHandler(state, OverviewHandlerOptions{ReadToken: overviewReadToken})
	if err != nil {
		t.Fatal(err)
	}
	routes := handler.Routes()

	unauthorized := httptest.NewRecorder()
	routes.ServeHTTP(unauthorized, httptest.NewRequest(http.MethodGet, "/api/v1/overview", nil))
	if unauthorized.Code != http.StatusUnauthorized || unauthorized.Header().Get("WWW-Authenticate") != "Bearer" {
		t.Fatalf("unauthorized response = %d, %q", unauthorized.Code, unauthorized.Header().Get("WWW-Authenticate"))
	}

	request := httptest.NewRequest(http.MethodGet, "/api/v1/overview", nil)
	request.Header.Set("Authorization", "Bearer "+overviewReadToken)
	response := httptest.NewRecorder()
	routes.ServeHTTP(response, request)
	if response.Code != http.StatusOK || response.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("response = %d, cache=%q", response.Code, response.Header().Get("Cache-Control"))
	}
	var snapshot OverviewSnapshot
	if err := json.NewDecoder(response.Body).Decode(&snapshot); err != nil {
		t.Fatal(err)
	}
	if snapshot.SchemaVersion != "1" || snapshot.Counts.ActiveRuns != "0" {
		t.Fatalf("snapshot = %#v", snapshot)
	}
}

func TestOverviewEventRejectsUnknownRunWithoutPartialCount(t *testing.T) {
	state := NewOverviewState(OverviewStateOptions{})
	if err := state.ObserveEvent(OverviewEventInput{RunID: "missing", PolicyHit: true, Blocked: true}); err != ErrOverviewRunNotFound {
		t.Fatalf("ObserveEvent error = %v", err)
	}
	snapshot, _ := state.Overview(t.Context())
	if snapshot.Counts.KernelEvents != "0" || snapshot.Counts.PolicyHits != "0" || snapshot.Counts.Blocked != "0" {
		t.Fatalf("failed event changed counts: %#v", snapshot.Counts)
	}
}
