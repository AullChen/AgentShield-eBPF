package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/agentshield/agentshield-ebpf/internal/api"
	"github.com/agentshield/agentshield-ebpf/internal/envcheck"
	"github.com/agentshield/agentshield-ebpf/internal/evidence"
	"github.com/agentshield/agentshield-ebpf/internal/policy"
	"github.com/agentshield/agentshield-ebpf/internal/store"
	"github.com/agentshield/agentshield-ebpf/internal/stream"
)

func TestRunRejectsConfigFileFlag(t *testing.T) {
	t.Setenv("AGENTSHIELD_CONFIG", "")

	if exitCode := run([]string{"version", "--config", "configs/agentshield.yaml"}); exitCode != 2 {
		t.Fatalf("run exit code = %d, want 2", exitCode)
	}
}

func TestRunRejectsConfigFileEnvironment(t *testing.T) {
	t.Setenv("AGENTSHIELD_CONFIG", "configs/agentshield.yaml")

	if exitCode := run([]string{"version"}); exitCode != 2 {
		t.Fatalf("run exit code = %d, want 2", exitCode)
	}
}

func TestRunCommandHelpExitsSuccessfully(t *testing.T) {
	t.Setenv("AGENTSHIELD_CONFIG", "")

	commands := []string{"audit", "serve", "diagnose", "health", "version"}
	for _, command := range commands {
		t.Run(command, func(t *testing.T) {
			if exitCode := run([]string{command, "--help"}); exitCode != 0 {
				t.Fatalf("run exit code = %d, want 0", exitCode)
			}
		})
	}
}

func TestManagedEntryRequiresSeparateTrustedSurfaces(t *testing.T) {
	if exitCode := run([]string{"serve"}); exitCode != 2 {
		t.Fatalf("incomplete serve=%d", exitCode)
	}
	options := managedOptions{managementSocket: "/run/agentshield/management.sock", databasePath: "/var/lib/agentshield/evidence.db", tokenFile: "/run/agentshield/read.token", policyPath: "configs/default-policies.yaml", networkRoot: "/sys/fs/cgroup", readAddress: "127.0.0.1:8080", ingestAddress: "127.0.0.1:8081"}
	aliased := options
	aliased.workloadSocket = options.managementSocket
	if aliased.validate() == nil {
		t.Fatal("management socket exposed as workload listener")
	}
	if err := options.validate(); err != nil {
		t.Fatal(err)
	}
	options.ingestAddress = "0.0.0.0:8081"
	if err := options.validate(); err == nil {
		t.Fatal("public ingest HTTP accepted")
	}
	options.ingestAddress = options.readAddress
	if err := options.validate(); err == nil {
		t.Fatal("shared ingest and read listener accepted")
	}
}

func TestManagedReadRoutesExposeDurableEvidenceButNoManagementOrIngest(t *testing.T) {
	database, err := store.OpenSQLite(filepath.Join(t.TempDir(), "evidence.db"), store.SQLiteOptions{})
	if errors.Is(err, store.ErrSQLiteUnavailable) {
		t.Skip(err)
	}
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	writer, err := store.NewWriter(database, store.WriterOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer writer.Close(context.Background())
	payload, err := json.Marshal(evidence.Event{ID: "durable-claim", Type: "tool_started", Source: evidence.AgentClaim, ServerMonotonicNS: 1, ServerUnixNS: 2, Summary: "stored claim"})
	if err != nil {
		t.Fatal(err)
	}
	if err := database.AppendBatch([]store.Record{{ID: "durable-claim", RecordType: "tool_started", RunID: "stored-run", Source: store.SourceAgentClaim, ServerMonotonicNS: 1, ServerUnixNS: 2, Payload: payload}}); err != nil {
		t.Fatal(err)
	}
	hub, err := stream.NewHub(stream.HubOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer hub.Close()
	generation := policy.Generation{Revision: 1, Bank: policy.BankA}
	diagnostics, err := api.NewDiagnosticsState(envcheck.Report{OS: "linux", Arch: "amd64"}, generation, api.DiagnosticsStateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	token := "managed-read-test-token-123456"
	routes, err := managedReadRoutes(token, hub, api.NewOverviewState(api.OverviewStateOptions{}), database, diagnostics, policy.Bundle{}, generation, &api.RuntimePipeline{}, writer)
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"/api/v1/overview", "/api/v1/evidence/stored-run", "/api/v1/policies", "/api/v1/diagnostics"} {
		request := httptest.NewRequest(http.MethodGet, path, nil)
		response := httptest.NewRecorder()
		routes.ServeHTTP(response, request)
		if response.Code != http.StatusUnauthorized {
			t.Fatalf("unauthenticated %s=%d", path, response.Code)
		}
		request.Header.Set("Authorization", "Bearer "+token)
		response = httptest.NewRecorder()
		routes.ServeHTTP(response, request)
		if response.Code != http.StatusOK || path == "/api/v1/evidence/stored-run" && !strings.Contains(response.Body.String(), "durable-claim") {
			t.Fatalf("authenticated %s=%d body=%s", path, response.Code, response.Body.String())
		}
	}
	for _, path := range []string{api.RegisterPath, "/ingest/v1/runs/stored-run/checkpoints"} {
		request := httptest.NewRequest(http.MethodPost, path, nil)
		request.Header.Set("Authorization", "Bearer "+token)
		response := httptest.NewRecorder()
		routes.ServeHTTP(response, request)
		if response.Code != http.StatusNotFound {
			t.Fatalf("mutating route on read API %s=%d", path, response.Code)
		}
	}
}

func TestRunRejectsUnexpectedArguments(t *testing.T) {
	t.Setenv("AGENTSHIELD_CONFIG", "")

	if exitCode := run([]string{"version", "unexpected"}); exitCode != 2 {
		t.Fatalf("run exit code = %d, want 2", exitCode)
	}
}

func TestAuditRequiresExactScope(t *testing.T) {
	t.Setenv("AGENTSHIELD_CONFIG", "")

	if exitCode := run([]string{"audit"}); exitCode != 2 {
		t.Fatalf("run(audit) = %d, want usage error 2", exitCode)
	}
	if exitCode := run([]string{
		"audit",
		"--cgroup", "/sys/fs/cgroup/one",
		"--scope-cgroup", "/sys/fs/cgroup/two",
	}); exitCode != 2 {
		t.Fatalf("run(audit with mismatched cgroups) = %d, want usage error 2", exitCode)
	}
}

func TestAuditLoadsPolicyBeforeInitializingKernelScope(t *testing.T) {
	t.Setenv("AGENTSHIELD_CONFIG", "")

	missing := filepath.Join(t.TempDir(), "missing.yaml")
	if exitCode := run([]string{
		"audit",
		"--scope-cgroup", "/not-resolved-before-policy-load",
		"--policy-file", missing,
	}); exitCode != 1 {
		t.Fatalf("run(audit with missing policy) = %d, want runtime error 1", exitCode)
	}
}

func TestValidateAuditPolicyScopesRejectsUnavailableContext(t *testing.T) {
	bundle := policy.Bundle{Policies: []policy.Policy{
		{ID: "global", Enabled: true, Scope: policy.Scope{Type: policy.ScopeGlobal}},
		{ID: "run-policy", Enabled: true, Scope: policy.Scope{Type: policy.ScopeRun, RunID: "run-1"}},
		{ID: "label-policy", Enabled: true, Scope: policy.Scope{Type: policy.ScopeLabels, LabelSelector: map[string]string{"team": "red"}}},
		{ID: "disabled-run", Enabled: false, Scope: policy.Scope{Type: policy.ScopeRun, RunID: "run-2"}},
	}}

	err := validateAuditPolicyScopes(bundle)
	if err == nil {
		t.Fatal("validateAuditPolicyScopes() accepted enabled run/label scopes")
	}
	message := err.Error()
	for _, expected := range []string{"run-policy", "run scope", "label-policy", "labels scope"} {
		if !strings.Contains(message, expected) {
			t.Fatalf("validation error %q does not contain %q", message, expected)
		}
	}
	if strings.Contains(message, "disabled-run") {
		t.Fatalf("validation error includes disabled policy: %q", message)
	}
}

func TestValidateAuditPolicyScopesAcceptsAvailableContext(t *testing.T) {
	bundle := policy.Bundle{Policies: []policy.Policy{
		{ID: "global", Enabled: true, Scope: policy.Scope{Type: policy.ScopeGlobal}},
		{ID: "cgroup", Enabled: true, Scope: policy.Scope{Type: policy.ScopeCgroup, CgroupID: "42"}},
	}}
	if err := validateAuditPolicyScopes(bundle); err != nil {
		t.Fatalf("validateAuditPolicyScopes() error = %v", err)
	}
}
