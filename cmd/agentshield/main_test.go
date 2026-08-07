package main

import (
	"path/filepath"
	"testing"
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
