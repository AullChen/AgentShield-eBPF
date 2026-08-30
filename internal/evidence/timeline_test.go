package evidence

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/agentshield/agentshield-ebpf/internal/correlator"
)

func TestP4Acceptance(t *testing.T) {
	timeline, err := BuildP4Sample()
	if err != nil {
		t.Fatalf("BuildP4Sample: %v", err)
	}
	if timeline.SchemaVersion != "1" || len(timeline.Items) != 6 {
		t.Fatalf("timeline = %+v", timeline)
	}
	seen := map[Source]bool{}
	for index, item := range timeline.Items {
		seen[item.Source] = true
		if item.Sequence == "" || item.ServerMonotonicNS == "" || item.ServerUnixNS == "" {
			t.Fatalf("item %d lost string identities: %+v", index, item)
		}
	}
	for _, source := range []Source{AgentClaim, KernelFact, PolicyDecision, ContainmentResult} {
		if !seen[source] {
			t.Fatalf("missing source %q", source)
		}
	}
	containment := timeline.Items[3]
	if containment.Containment == nil || containment.Containment.OriginalActionResult != "none" || containment.Containment.Result != "killed" {
		t.Fatalf("containment = %+v", containment)
	}
	blocked := timeline.Items[4]
	if blocked.Operation == nil || blocked.Operation.ActionResult != "blocked" || blocked.Operation.Mechanism != "cgroup/connect4" {
		t.Fatalf("blocked operation = %+v", blocked)
	}

	goldenPath := filepath.Join("..", "..", "docs", "examples", "p4-evidence-timeline.json")
	golden, err := os.ReadFile(goldenPath)
	if err != nil {
		t.Fatalf("read golden: %v", err)
	}
	var tracked Timeline
	if err := json.Unmarshal(golden, &tracked); err != nil {
		t.Fatalf("decode golden: %v", err)
	}
	want, _ := json.Marshal(timeline)
	got, _ := json.Marshal(tracked)
	if string(want) != string(got) {
		t.Fatalf("tracked P4 sample is stale\nwant %s\ngot  %s", want, got)
	}
}

func TestTimelineRejectsSourceConfusion(t *testing.T) {
	tests := []Event{
		{ID: "claim-operation", Type: "claim", Source: AgentClaim, Operation: &OperationResult{}},
		{ID: "claim-attribution", Type: "claim", Source: AgentClaim, Attribution: &Attribution{Status: "exact"}},
		{ID: "claim-correlation", Type: "claim", Source: AgentClaim, Correlation: &correlator.Result{}},
		{ID: "decision-operation", Type: "decision", Source: PolicyDecision, Decision: &Decision{}, Operation: &OperationResult{}},
		{ID: "containment-attribution", Type: "containment", Source: ContainmentResult, Containment: &Containment{}, Attribution: &Attribution{}},
	}
	for _, event := range tests {
		event.ServerMonotonicNS = 1
		event.ServerUnixNS = 2
		event.Summary = "confused source"
		if _, err := Build("run", []Event{event}); err == nil {
			t.Fatalf("source-confused event was accepted: %+v", event)
		}
	}
}

func TestTimelineRejectsCrossRunAndCrossSourceReferences(t *testing.T) {
	claim := Event{ID: "checkpoint", Type: "tool_started", Source: AgentClaim, ServerMonotonicNS: 1, ServerUnixNS: 2, Summary: "claim"}
	kernel := Event{
		ID: "kernel", Type: "exec_attempt", Source: KernelFact, ServerMonotonicNS: 2, ServerUnixNS: 3,
		Summary: "observed", Operation: &OperationResult{AttemptObserved: true, ActionResult: "none", Mechanism: "tracepoint"},
	}
	tests := []struct {
		name   string
		mutate func(*Event)
	}{
		{name: "attribution Run", mutate: func(event *Event) {
			event.Attribution = &Attribution{Status: "exact", RunID: "other-run"}
		}},
		{name: "correlation event", mutate: func(event *Event) {
			event.Correlation = &correlator.Result{EventID: "other-event"}
		}},
		{name: "correlation Run", mutate: func(event *Event) {
			event.Correlation = &correlator.Result{EventID: event.ID, Attribution: correlator.Attribution{RunID: "other-run"}}
		}},
		{name: "selected non-claim", mutate: func(event *Event) {
			event.Correlation = &correlator.Result{EventID: event.ID, SelectedCheckpoint: event.ID}
		}},
		{name: "missing candidate", mutate: func(event *Event) {
			event.Correlation = &correlator.Result{EventID: event.ID, Candidates: []correlator.Candidate{{CheckpointID: "missing"}}}
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			candidate := kernel
			test.mutate(&candidate)
			if _, err := Build("run", []Event{claim, candidate}); err == nil {
				t.Fatal("invalid evidence reference was accepted")
			}
		})
	}
}
