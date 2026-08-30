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
