package policy

import (
	"strings"
	"testing"
)

func TestMatchExecMatchesExecutableBasename(t *testing.T) {
	policy := execPolicy(ActionAlert)
	policy.Conditions.Exec.Executables = []string{"sh", "curl"}
	result, err := MatchExec(
		Bundle{SchemaVersion: SchemaVersion, Policies: []Policy{policy}},
		ExecObservation{
			Operation: ExecOperationExecve, Executable: "/usr/bin/sh",
			ArgumentsState: CaptureComplete,
		},
	)
	if err != nil {
		t.Fatalf("MatchExec: %v", err)
	}
	if len(result.Hits) != 1 || result.Hits[0].RuleKind != "exec_executable" {
		t.Fatalf("hits = %+v", result.Hits)
	}
	hit := result.Hits[0]
	if hit.RuleID == 0 || hit.Confidence != ConfidenceHeuristic || !hit.PostEventOnly {
		t.Fatalf("hit semantics = %+v", hit)
	}
	if !containsString(hit.Reasons, "exec_attempt_not_execution_result") {
		t.Fatalf("reasons = %v", hit.Reasons)
	}
}

func TestMatchExecMatchesBoundedArgumentSummary(t *testing.T) {
	policy := execPolicy(ActionAlert)
	policy.Conditions.Exec = &ExecCondition{ArgContains: []string{"rm -rf"}}
	result, err := MatchExec(
		Bundle{SchemaVersion: SchemaVersion, Policies: []Policy{policy}},
		ExecObservation{
			Operation: ExecOperationExecve, Executable: "/usr/bin/rm",
			Arguments: []string{"rm", "-rf", "/tmp/example"}, ArgumentsState: CaptureComplete,
		},
	)
	if err != nil {
		t.Fatalf("MatchExec: %v", err)
	}
	if len(result.Hits) != 1 || result.Hits[0].RuleKind != "exec_argument" {
		t.Fatalf("hits = %+v", result.Hits)
	}
}

func TestMatchExecUnavailableAndEmptyArgumentsAreDistinct(t *testing.T) {
	policy := execPolicy(ActionAlert)
	policy.Conditions.Exec = &ExecCondition{
		Executables: []string{"sh"}, ArgContains: []string{"curl"},
	}
	unavailable, err := MatchExec(
		Bundle{SchemaVersion: SchemaVersion, Policies: []Policy{policy}},
		ExecObservation{Operation: ExecOperationExecve, Executable: "sh", ArgumentsState: CaptureUnavailable},
	)
	if err != nil {
		t.Fatalf("MatchExec unavailable: %v", err)
	}
	if len(unavailable.Hits) != 1 || !hasGap(unavailable.Gaps, "arguments_unavailable") {
		t.Fatalf("unavailable result = %+v", unavailable)
	}
	empty, err := MatchExec(
		Bundle{SchemaVersion: SchemaVersion, Policies: []Policy{policy}},
		ExecObservation{Operation: ExecOperationExecve, Executable: "sh", Arguments: []string{}, ArgumentsState: CaptureComplete},
	)
	if err != nil {
		t.Fatalf("MatchExec empty: %v", err)
	}
	if len(empty.Hits) != 1 || hasGap(empty.Gaps, "arguments_unavailable") {
		t.Fatalf("empty result = %+v", empty)
	}
}

func TestMatchExecTruncatedArgumentsCanOnlyProduceIncompletePositiveHit(t *testing.T) {
	policy := execPolicy(ActionAlert)
	policy.Conditions.Exec = &ExecCondition{ArgContains: []string{"curl"}}
	result, err := MatchExec(
		Bundle{SchemaVersion: SchemaVersion, Policies: []Policy{policy}},
		ExecObservation{
			Operation: ExecOperationExecve, Executable: "sh",
			Arguments: []string{"curl", "https://example.invalid/very-long"}, ArgumentsState: CaptureTruncated,
		},
	)
	if err != nil {
		t.Fatalf("MatchExec: %v", err)
	}
	if len(result.Hits) != 1 || result.Hits[0].Confidence != ConfidenceIncomplete {
		t.Fatalf("hits = %+v", result.Hits)
	}
	if !hasGap(result.Gaps, "arguments_truncated") {
		t.Fatalf("gaps = %+v", result.Gaps)
	}
}

func TestMatchExecSuppressesTruncatedExecutableMatch(t *testing.T) {
	policy := execPolicy(ActionAlert)
	policy.Conditions.Exec = &ExecCondition{Executables: []string{"curl"}}
	result, err := MatchExec(
		Bundle{SchemaVersion: SchemaVersion, Policies: []Policy{policy}},
		ExecObservation{
			Operation: ExecOperationExecve, Executable: "curl", ExecutableTruncated: true,
			ArgumentsState: CaptureComplete,
		},
	)
	if err != nil {
		t.Fatalf("MatchExec: %v", err)
	}
	if len(result.Hits) != 0 || !hasGap(result.Gaps, "executable_truncated") {
		t.Fatalf("result = %+v", result)
	}
}

func TestMatchExecveatReportsUnresolvedRelativePath(t *testing.T) {
	policy := execPolicy(ActionAlert)
	policy.Conditions.Exec = &ExecCondition{Executables: []string{"sh"}}
	result, err := MatchExec(
		Bundle{SchemaVersion: SchemaVersion, Policies: []Policy{policy}},
		ExecObservation{
			Operation: ExecOperationExecveat, Executable: "bin/sh",
			ArgumentsState: CaptureComplete, ExecveatFlags: 0x1000,
		},
	)
	if err != nil {
		t.Fatalf("MatchExec: %v", err)
	}
	if len(result.Hits) != 1 || !containsString(result.Hits[0].Reasons, "execveat_attempt") {
		t.Fatalf("hits = %+v", result.Hits)
	}
	if !hasGap(result.Gaps, "execveat_resolution_unavailable") {
		t.Fatalf("gaps = %+v", result.Gaps)
	}
}

func TestMatchExecContainmentIsOnlyAHint(t *testing.T) {
	policy := execPolicy(ActionContain)
	policy.Conditions.Exec = &ExecCondition{Executables: []string{"sh"}}
	result, err := MatchExec(
		Bundle{SchemaVersion: SchemaVersion, Policies: []Policy{policy}},
		ExecObservation{Operation: ExecOperationExecve, Executable: "sh", ArgumentsState: CaptureComplete},
	)
	if err != nil {
		t.Fatalf("MatchExec: %v", err)
	}
	if len(result.Hits) != 1 {
		t.Fatalf("hits = %+v", result.Hits)
	}
	hit := result.Hits[0]
	if hit.RequestedAction != ActionContain || hit.EffectiveAction != ActionAlert || !hit.ContainmentHint {
		t.Fatalf("containment semantics = %+v", hit)
	}
}

func TestMatchExecRejectsBlock(t *testing.T) {
	policy := execPolicy(ActionBlock)
	_, err := MatchExec(
		Bundle{SchemaVersion: SchemaVersion, Policies: []Policy{policy}},
		ExecObservation{Operation: ExecOperationExecve, Executable: "sh", ArgumentsState: CaptureComplete},
	)
	if err == nil || !strings.Contains(err.Error(), "containment hint") {
		t.Fatalf("block error = %v", err)
	}
}

func execPolicy(action Action) Policy {
	policy := validPolicy()
	policy.ID = "builtin.exec.test"
	policy.Conditions = Conditions{Exec: &ExecCondition{Executables: []string{"sh"}}}
	policy.RequestedAction = action
	if action == ActionContain || action == ActionBlock {
		policy.Decision = DecisionDeny
	}
	return policy
}

func hasGap(gaps []EvaluationGap, code string) bool {
	for _, gap := range gaps {
		if gap.Code == code {
			return true
		}
	}
	return false
}
