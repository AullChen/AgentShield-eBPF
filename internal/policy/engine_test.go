package policy

import (
	"fmt"
	"net/netip"
	"sync"
	"testing"
)

func TestEngineRetainsAllHitsAndUsesDeterministicPrecedence(t *testing.T) {
	policies := []Policy{
		filePolicy("global", Scope{Type: ScopeGlobal}, 500, "/shared"),
		filePolicy("labels", Scope{Type: ScopeLabels, LabelSelector: map[string]string{"team": "red"}}, -5, "/shared"),
		filePolicy("cgroup", Scope{Type: ScopeCgroup, CgroupID: "42"}, -100, "/shared"),
		filePolicy("run", Scope{Type: ScopeRun, RunID: "run-7"}, -1000, "/shared"),
	}
	engine := mustEngine(t, Bundle{SchemaVersion: SchemaVersion, Policies: policies}, Generation{Revision: 1, Bank: BankA})

	report, err := engine.EvaluateFile(EvaluationContext{
		RunID: "run-7", CgroupID: "42", Labels: map[string]string{"team": "red"},
	}, FileObservation{UserPath: "/shared", Access: FileRead})
	if err != nil {
		t.Fatalf("EvaluateFile() error = %v", err)
	}
	wantOrder := []string{"run", "cgroup", "labels", "global"}
	if len(report.Hits) != len(wantOrder) {
		t.Fatalf("hit count = %d, want %d: %+v", len(report.Hits), len(wantOrder), report.Hits)
	}
	for index, want := range wantOrder {
		if report.Hits[index].PolicyID != want {
			t.Fatalf("hit[%d] policy = %q, want %q", index, report.Hits[index].PolicyID, want)
		}
	}
	if report.Final == nil || report.Final.PolicyID != "run" {
		t.Fatalf("final = %+v, want run policy", report.Final)
	}
	if report.Generation != (Generation{Revision: 1, Bank: BankA}) {
		t.Fatalf("generation = %+v", report.Generation)
	}
}

func TestEngineUsesPriorityThenPolicyIDWithinScope(t *testing.T) {
	policies := []Policy{
		filePolicy("z-low", Scope{Type: ScopeGlobal}, 1, "/shared"),
		filePolicy("z-high", Scope{Type: ScopeGlobal}, 2, "/shared"),
		filePolicy("a-high", Scope{Type: ScopeGlobal}, 2, "/shared"),
	}
	engine := mustEngine(t, Bundle{SchemaVersion: SchemaVersion, Policies: policies}, Generation{Revision: 1, Bank: BankA})

	report, err := engine.EvaluateFile(EvaluationContext{}, FileObservation{UserPath: "/shared", Access: FileRead})
	if err != nil {
		t.Fatalf("EvaluateFile() error = %v", err)
	}
	if report.Final == nil || report.Final.PolicyID != "a-high" {
		t.Fatalf("final = %+v, want lexical winner a-high", report.Final)
	}
}

func TestEngineEvaluatesFileAndExecPolicies(t *testing.T) {
	execPolicy := filePolicy("exec", Scope{Type: ScopeGlobal}, 10, "/unused")
	execPolicy.Conditions = Conditions{Exec: &ExecCondition{Executables: []string{"bash"}}}
	bundle := Bundle{SchemaVersion: SchemaVersion, Policies: []Policy{
		filePolicy("file", Scope{Type: ScopeGlobal}, 10, "/secret"),
		execPolicy,
	}}
	engine := mustEngine(t, bundle, Generation{Revision: 1, Bank: BankA})

	fileReport, err := engine.EvaluateFile(EvaluationContext{}, FileObservation{UserPath: "/secret", Access: FileRead})
	if err != nil || fileReport.Final == nil || fileReport.Final.PolicyID != "file" {
		t.Fatalf("file report = %+v, error = %v", fileReport, err)
	}
	execReport, err := engine.EvaluateExec(EvaluationContext{}, ExecObservation{
		Operation: ExecOperationExecve, Executable: "/usr/bin/bash", ArgumentsState: CaptureComplete,
	})
	if err != nil || execReport.Final == nil || execReport.Final.PolicyID != "exec" {
		t.Fatalf("exec report = %+v, error = %v", execReport, err)
	}
}

func TestEngineNetworkFinalRetainsMoreSpecificAllow(t *testing.T) {
	specific := strictProxyPolicy()
	specific.ID = "cgroup-allow"
	specific.Scope = Scope{Type: ScopeCgroup, CgroupID: "42"}
	specific.Priority = -100
	lower := strictProxyPolicy()
	lower.ID = "global-deny"
	lower.Scope = Scope{Type: ScopeGlobal}
	lower.Priority = 100
	lower.Conditions.Network.CIDRs = []string{"198.51.100.1/32"}
	engine := mustEngine(t, Bundle{SchemaVersion: SchemaVersion, Policies: []Policy{lower, specific}}, Generation{Revision: 1, Bank: BankA})

	report, err := engine.EvaluateNetwork(
		EvaluationContext{CgroupID: "42"},
		NetworkObservation{Destination: netip.MustParseAddr("192.0.2.10"), Port: 3128, Protocol: ProtocolTCP},
	)
	if err != nil {
		t.Fatalf("EvaluateNetwork() error = %v", err)
	}
	if report.Final == nil || report.Final.PolicyID != "cgroup-allow" ||
		report.Final.NetworkDisposition != DispositionAllowed {
		t.Fatalf("final = %+v, want cgroup allow", report.Final)
	}
	if len(report.Hits) != 2 || report.Hits[0].PolicyID != "cgroup-allow" ||
		report.Hits[0].RuleKind != "network_allow" {
		t.Fatalf("hits = %+v, want more-specific allow before global deny", report.Hits)
	}
}

func TestEngineActivationIsImmutableAndFailureAtomic(t *testing.T) {
	initial := Bundle{SchemaVersion: SchemaVersion, Policies: []Policy{
		filePolicy("old", Scope{Type: ScopeGlobal}, 1, "/old"),
	}}
	engine := mustEngine(t, initial, Generation{Revision: 3, Bank: BankA})
	initial.Policies[0].Conditions.File.ExactPaths[0] = "/mutated"

	report, err := engine.EvaluateFile(EvaluationContext{}, FileObservation{UserPath: "/old", Access: FileRead})
	if err != nil || report.Final == nil || report.Final.PolicyID != "old" {
		t.Fatalf("immutable report = %+v, error = %v", report, err)
	}

	invalid := Bundle{SchemaVersion: SchemaVersion, Policies: []Policy{
		filePolicy("invalid", Scope{Type: ScopeGlobal}, 1, "/invalid"),
	}}
	invalid.Policies[0].RequestedAction = ActionBlock
	invalid.Policies[0].Decision = DecisionDeny
	if _, err := engine.Activate(invalid, Generation{Revision: 4, Bank: BankB}); err == nil {
		t.Fatal("Activate() accepted a file block policy unsupported by the evaluator")
	}
	report, err = engine.EvaluateFile(EvaluationContext{}, FileObservation{UserPath: "/old", Access: FileRead})
	if err != nil || report.Generation.Revision != 3 || report.Final == nil || report.Final.PolicyID != "old" {
		t.Fatalf("failed activation changed snapshot: report = %+v, error = %v", report, err)
	}

	next := Bundle{SchemaVersion: SchemaVersion, Policies: []Policy{
		filePolicy("new", Scope{Type: ScopeGlobal}, 1, "/new"),
	}}
	if _, err := engine.Activate(next, Generation{Revision: 4, Bank: BankB}); err != nil {
		t.Fatalf("Activate() error = %v", err)
	}
	report, err = engine.EvaluateFile(EvaluationContext{}, FileObservation{UserPath: "/new", Access: FileRead})
	if err != nil || report.Generation != (Generation{Revision: 4, Bank: BankB}) || report.Final == nil || report.Final.PolicyID != "new" {
		t.Fatalf("new report = %+v, error = %v", report, err)
	}
}

func TestEngineConcurrentActivationNeverMixesGenerationAndPolicy(t *testing.T) {
	oldBundle := Bundle{SchemaVersion: SchemaVersion, Policies: []Policy{
		filePolicy("old", Scope{Type: ScopeGlobal}, 1, "/shared"),
	}}
	newBundle := Bundle{SchemaVersion: SchemaVersion, Policies: []Policy{
		filePolicy("new", Scope{Type: ScopeGlobal}, 1, "/shared"),
	}}
	engine := mustEngine(t, oldBundle, Generation{Revision: 1, Bank: BankA})

	start := make(chan struct{})
	results := make(chan DecisionReport, 64)
	var wait sync.WaitGroup
	for range 64 {
		wait.Add(1)
		go func() {
			defer wait.Done()
			<-start
			report, err := engine.EvaluateFile(EvaluationContext{}, FileObservation{UserPath: "/shared", Access: FileRead})
			if err != nil {
				t.Errorf("EvaluateFile() error = %v", err)
				return
			}
			results <- report
		}()
	}
	close(start)
	if _, err := engine.Activate(newBundle, Generation{Revision: 2, Bank: BankB}); err != nil {
		t.Fatalf("Activate() error = %v", err)
	}
	wait.Wait()
	close(results)
	for report := range results {
		if report.Final == nil {
			t.Fatal("concurrent report has no final decision")
		}
		pair := fmt.Sprintf("%d/%s", report.Generation.Revision, report.Final.PolicyID)
		if pair != "1/old" && pair != "2/new" {
			t.Fatalf("mixed generation/policy report: %s", pair)
		}
	}
}

func filePolicy(id string, scope Scope, priority int, exactPath string) Policy {
	policy := validPolicy()
	policy.ID = id
	policy.Name = id
	policy.Scope = scope
	policy.Priority = priority
	policy.Conditions.File.ExactPaths = []string{exactPath}
	return policy
}

func mustEngine(t *testing.T, bundle Bundle, generation Generation) *Engine {
	t.Helper()
	engine, _, err := NewEngine(bundle, generation, Limits{})
	if err != nil {
		t.Fatalf("NewEngine() error = %v", err)
	}
	return engine
}
