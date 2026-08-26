package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/agentshield/agentshield-ebpf/internal/policy"
)

const policyReadToken = "policy-read-token-1234567890"

func TestPolicyCatalogReportsLoadedBundleAndEnabledState(t *testing.T) {
	now := time.Date(2026, 8, 26, 2, 0, 0, 0, time.UTC)
	bundle := policy.Bundle{SchemaVersion: policy.SchemaVersion, Policies: []policy.Policy{
		{ID: "lower", Name: "Lower", Enabled: false, Scope: policy.Scope{Type: policy.ScopeGlobal},
			Decision: policy.DecisionObserve, RequestedAction: policy.ActionAudit, Severity: policy.SeverityInfo,
			Priority: 10, Conditions: policy.Conditions{Exec: &policy.ExecCondition{Executables: []string{"sh"}}}},
		{ID: "higher", Name: "Higher", Enabled: true, Scope: policy.Scope{Type: policy.ScopeRun, RunID: "run-1"},
			Decision: policy.DecisionDeny, RequestedAction: policy.ActionContain, Severity: policy.SeverityHigh,
			Priority: 20, Conditions: policy.Conditions{File: &policy.FileCondition{ExactPaths: []string{"/secret"}, Access: []policy.FileAccess{policy.FileRead}}}},
	}}
	catalog, err := NewPolicyCatalog(&bundle, policy.Generation{Revision: 7, Bank: policy.BankB}, PolicyCatalogOptions{Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := catalog.Policies(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if !snapshot.Configured || snapshot.Generation.Revision != "7" || snapshot.Generation.Bank != "B" ||
		len(snapshot.Policies) != 2 || snapshot.Policies[0].ID != "higher" || !snapshot.Policies[0].Enabled ||
		snapshot.Policies[0].Scope != "run:run-1" || snapshot.Policies[0].Condition != "file" {
		t.Fatalf("snapshot = %#v", snapshot)
	}
}

func TestPolicyHandlerIsAuthenticatedAndReadOnly(t *testing.T) {
	catalog, err := NewPolicyCatalog(nil, policy.Generation{}, PolicyCatalogOptions{})
	if err != nil {
		t.Fatal(err)
	}
	handler, err := NewPolicyHandler(catalog, PolicyHandlerOptions{ReadToken: policyReadToken})
	if err != nil {
		t.Fatal(err)
	}
	unauthorized := httptest.NewRecorder()
	handler.Routes().ServeHTTP(unauthorized, httptest.NewRequest(http.MethodGet, "/api/v1/policies", nil))
	if unauthorized.Code != http.StatusUnauthorized {
		t.Fatalf("unauthorized status = %d", unauthorized.Code)
	}
	post := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/api/v1/policies", nil)
	request.Header.Set("Authorization", "Bearer "+policyReadToken)
	handler.Routes().ServeHTTP(post, request)
	if post.Code != http.StatusMethodNotAllowed {
		t.Fatalf("POST status = %d, want 405", post.Code)
	}
	get := httptest.NewRecorder()
	request = httptest.NewRequest(http.MethodGet, "/api/v1/policies", nil)
	request.Header.Set("Authorization", "Bearer "+policyReadToken)
	handler.Routes().ServeHTTP(get, request)
	if get.Code != http.StatusOK || get.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("GET status = %d, cache = %q", get.Code, get.Header().Get("Cache-Control"))
	}
	var snapshot PolicySnapshot
	if err := json.NewDecoder(get.Body).Decode(&snapshot); err != nil {
		t.Fatal(err)
	}
	if snapshot.Configured || snapshot.Policies == nil {
		t.Fatalf("unconfigured snapshot = %#v", snapshot)
	}
}
