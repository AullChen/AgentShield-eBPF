package correlator

import (
	"math/rand"
	"reflect"
	"testing"
)

func TestCorrelatorUsesTwoStageRunThenCheckpointMatching(t *testing.T) {
	correlator, _ := New(func(instance, cookie, _ uint64) Attribution {
		if instance == 7 && cookie == 9 {
			return Attribution{RunID: "run-a", RunStatus: "active", Status: AttributionExact}
		}
		return Attribution{Status: AttributionUnknown}
	}, Options{})
	event := KernelEvent{EventID: "event-1", InstanceID: 7, ScopeCookie: 9, ServerMonotonicNS: 10_000_000_000, PID: 42, TGID: 40, EventType: "exec_attempt", ToolName: "shell"}
	result := correlator.Correlate(event, []Checkpoint{
		{CheckpointID: "other-run", RunID: "run-b", ServerMonotonicNS: 10_000_000_000, PID: 42, ToolName: "shell", Type: "tool_started"},
		{CheckpointID: "selected", RunID: "run-a", ServerMonotonicNS: 9_900_000_000, TGID: 40, ToolName: "SHELL", Type: "tool_started", ClientUnixNS: 1},
	})
	if result.SelectedCheckpoint != "selected" || result.Confidence != 99 || result.Attribution.Status != AttributionExact {
		t.Fatalf("result = %+v", result)
	}
	for _, factor := range result.Candidates[0].Factors {
		if factor.Name == "run_id" || factor.Name == "cgroup" || factor.Name == "client_time" {
			t.Fatalf("duplicated/untrusted factor = %+v", factor)
		}
	}
}

func TestCorrelatorReportsEqualConflictDeterministically(t *testing.T) {
	correlator, _ := New(func(_, _, _ uint64) Attribution { return Attribution{RunID: "run", Status: AttributionExact} }, Options{})
	event := KernelEvent{EventID: "event", InstanceID: 1, ScopeCookie: 2, ServerMonotonicNS: 5_000_000_000, EventType: "file_open", ToolName: "python"}
	original := []Checkpoint{
		{CheckpointID: "b", RunID: "run", ServerMonotonicNS: 5_000_000_000, Type: "tool_started", ToolName: "python"},
		{CheckpointID: "a", RunID: "run", ServerMonotonicNS: 5_000_000_000, Type: "tool_started", ToolName: "python"},
	}
	first := correlator.Correlate(event, original)
	rand.New(rand.NewSource(1)).Shuffle(len(original), func(i, j int) { original[i], original[j] = original[j], original[i] })
	second := correlator.Correlate(event, original)
	if !first.Conflict || first.SelectedCheckpoint != "" || first.CorrelationStatus != "ambiguous" {
		t.Fatalf("result = %+v", first)
	}
	if !reflect.DeepEqual(first, second) {
		t.Fatalf("input order changed result: first=%+v second=%+v", first, second)
	}
}

func TestCorrelatorRejectsStaleAndOutOfWindowCandidates(t *testing.T) {
	stale, _ := New(func(_, _, _ uint64) Attribution { return Attribution{Status: AttributionStale} }, Options{})
	event := KernelEvent{EventID: "event", InstanceID: 1, ScopeCookie: 2, ServerMonotonicNS: 10_000_000_000}
	if result := stale.Correlate(event, nil); result.CorrelationStatus != "unattributed" {
		t.Fatalf("stale result = %+v", result)
	}
	exact, _ := New(func(_, _, _ uint64) Attribution { return Attribution{RunID: "run", Status: AttributionExact} }, Options{})
	result := exact.Correlate(event, []Checkpoint{{CheckpointID: "late", RunID: "run", ServerMonotonicNS: 20_000_000_000, Type: "tool_started"}})
	if result.CorrelationStatus != "unmatched" || len(result.Candidates) != 0 {
		t.Fatalf("out of window result = %+v", result)
	}
}

func TestScoreIsClamped(t *testing.T) {
	correlator, _ := New(func(_, _, _ uint64) Attribution { return Attribution{RunID: "run", Status: AttributionExact} }, Options{})
	result := correlator.Correlate(KernelEvent{EventID: "event", InstanceID: 1, ScopeCookie: 2, ServerMonotonicNS: 100, TGID: 3, EventType: "net_connect", ToolName: "http"},
		[]Checkpoint{{CheckpointID: "cp", RunID: "run", ServerMonotonicNS: 100, TGID: 3, Type: "tool_started", ToolName: "http"}})
	if result.Confidence != 100 {
		t.Fatalf("confidence = %d", result.Confidence)
	}
}
