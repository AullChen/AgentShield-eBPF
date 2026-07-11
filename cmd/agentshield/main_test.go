package main

import "testing"

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
