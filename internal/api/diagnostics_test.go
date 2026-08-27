package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/agentshield/agentshield-ebpf/internal/envcheck"
	"github.com/agentshield/agentshield-ebpf/internal/policy"
)

const diagnosticsReadToken = "diagnostics-read-token-123456"

func TestDiagnosticsRequiresActualLoadAttachSignal(t *testing.T) {
	now := time.Date(2026, 8, 27, 2, 0, 0, 0, time.UTC)
	report := envcheck.Report{OS: "linux", Arch: "amd64", Checks: []envcheck.Check{
		{Name: "btf", Status: envcheck.StatusPass, Message: "file exists"},
		{Name: "bpf_permissions", Status: envcheck.StatusPass, Message: "fixture says pass"},
	}}
	state, err := NewDiagnosticsState(report, policy.Generation{Revision: 3, Bank: policy.BankA}, DiagnosticsStateOptions{Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	before, err := state.Diagnostics(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if before.LoadAttach.Status != "unknown" || before.PolicyGeneration.Revision != "3" || len(before.Hooks) != 4 {
		t.Fatalf("before actual probe = %#v", before)
	}
	state.MarkHooksReady()
	if err := state.ObserveDrop("exec_attempt", 2); err != nil {
		t.Fatal(err)
	}
	if err := state.ObserveDrop("exec_attempt", 3); err != nil {
		t.Fatal(err)
	}
	after, err := state.Diagnostics(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if after.LoadAttach.Status != "available" || after.Hooks[0].Status != "attached" ||
		len(after.Drops) != 1 || after.Drops[0].EventType != "exec_attempt" || after.Drops[0].Count != "5" {
		t.Fatalf("after actual probe = %#v", after)
	}
}

func TestDiagnosticsHandlerRequiresReadToken(t *testing.T) {
	state, err := NewDiagnosticsState(envcheck.Report{OS: "linux", Arch: "arm64"}, policy.Generation{}, DiagnosticsStateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	handler, err := NewDiagnosticsHandler(state, DiagnosticsHandlerOptions{ReadToken: diagnosticsReadToken})
	if err != nil {
		t.Fatal(err)
	}
	unauthorized := httptest.NewRecorder()
	handler.Routes().ServeHTTP(unauthorized, httptest.NewRequest(http.MethodGet, "/api/v1/diagnostics", nil))
	if unauthorized.Code != http.StatusUnauthorized {
		t.Fatalf("unauthorized status = %d", unauthorized.Code)
	}
	request := httptest.NewRequest(http.MethodGet, "/api/v1/diagnostics", nil)
	request.Header.Set("Authorization", "Bearer "+diagnosticsReadToken)
	response := httptest.NewRecorder()
	handler.Routes().ServeHTTP(response, request)
	if response.Code != http.StatusOK || response.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("response status = %d, cache = %q", response.Code, response.Header().Get("Cache-Control"))
	}
	var snapshot DiagnosticsSnapshot
	if err := json.NewDecoder(response.Body).Decode(&snapshot); err != nil {
		t.Fatal(err)
	}
	if snapshot.SchemaVersion != "1" || (snapshot.ByteOrder != "little-endian" && snapshot.ByteOrder != "big-endian") || snapshot.Drops == nil {
		t.Fatalf("snapshot = %#v", snapshot)
	}
}
