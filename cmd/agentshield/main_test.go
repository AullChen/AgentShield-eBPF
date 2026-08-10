package main

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/agentshield/agentshield-ebpf/internal/policy"
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

	commands := []string{"audit", "diagnose", "health", "version"}
	for _, command := range commands {
		t.Run(command, func(t *testing.T) {
			if exitCode := run([]string{command, "--help"}); exitCode != 0 {
				t.Fatalf("run exit code = %d, want 0", exitCode)
			}
		})
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
