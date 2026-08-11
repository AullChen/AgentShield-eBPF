package policy

import (
	"net/netip"
	"testing"

	"github.com/agentshield/agentshield-ebpf/internal/events"
)

func TestEvaluateAuditEventRetainsReadWriteHitsAndFinalDecision(t *testing.T) {
	readPolicy := filePolicy("read", Scope{Type: ScopeGlobal}, 1, "/shared")
	writePolicy := filePolicy("write", Scope{Type: ScopeCgroup, CgroupID: "42"}, -100, "/shared")
	writePolicy.Conditions.File.Access = []FileAccess{FileWrite}
	engine := mustEngine(t, Bundle{SchemaVersion: SchemaVersion, Policies: []Policy{readPolicy, writePolicy}}, Generation{Revision: 7, Bank: BankA})

	records, err := engine.EvaluateAuditEvent(events.KernelEvent{
		EventType: events.EventTypeFileOpen, EventTypeName: "file_open",
		KernelMonotonicNS: 100, CgroupID: 42, InstanceID: 2, ScopeCookie: 3,
		PID: 10, Data: "/shared", SyscallFlags: openReadWrite,
	})
	if err != nil {
		t.Fatalf("EvaluateAuditEvent() error = %v", err)
	}
	record := records[0].(AuditDecisionRecord)
	if len(record.Hits) != 2 {
		t.Fatalf("hits = %+v, want read and write hits", record.Hits)
	}
	if record.Final == nil || record.Final.PolicyID != "write" {
		t.Fatalf("final = %+v, want cgroup-scoped write policy", record.Final)
	}
	if record.Generation != (Generation{Revision: 7, Bank: BankA}) {
		t.Fatalf("generation = %+v", record.Generation)
	}
}

func TestEvaluateAuditEventReconcilesKernelNetworkBlock(t *testing.T) {
	blockPolicy := strictProxyPolicy()
	engine := mustEngine(t, Bundle{SchemaVersion: SchemaVersion, Policies: []Policy{blockPolicy}}, Generation{Revision: 1, Bank: BankA})
	matched, err := MatchNetwork(Bundle{SchemaVersion: SchemaVersion, Policies: []Policy{blockPolicy}}, NetworkObservation{
		Destination: netip.MustParseAddr("198.51.100.8"), Port: 443, Protocol: ProtocolTCP,
	})
	if err != nil {
		t.Fatalf("MatchNetwork() error = %v", err)
	}

	records, err := engine.EvaluateAuditEvent(events.KernelEvent{
		EventType: events.EventTypeNetConnect, EventTypeName: "net_connect",
		Action: events.ActionBlock, ActionResult: events.ActionResultBlocked,
		PolicyID: stablePolicyID(blockPolicy.ID), RuleID: matched.Hits[0].RuleID, CgroupID: 42,
		DestinationIP: "198.51.100.8", DestinationPort: 443, Protocol: events.ProtocolTCP,
	})
	if err != nil {
		t.Fatalf("EvaluateAuditEvent() error = %v", err)
	}
	record := records[0].(AuditDecisionRecord)
	if record.Final == nil || !record.Final.Enforced || record.Final.EffectiveAction != ActionBlock {
		t.Fatalf("final = %+v", record.Final)
	}
	if len(record.Hits) != 1 || !record.Hits[0].Enforced || record.Hits[0].PostEventOnly ||
		!containsString(record.Hits[0].Reasons, "cgroup_connect_hook_blocked") ||
		containsString(record.Hits[0].Reasons, "enforcement_not_connected") {
		t.Fatalf("hit = %+v", record.Hits)
	}
	if len(record.NetworkDecisions) != 1 || !record.NetworkDecisions[0].Enforced {
		t.Fatalf("network decisions = %+v", record.NetworkDecisions)
	}
}

func TestEvaluateAuditEventReconcilesKernelNetworkAllow(t *testing.T) {
	allowPolicy := strictProxyPolicy()
	engine := mustEngine(t, Bundle{SchemaVersion: SchemaVersion, Policies: []Policy{allowPolicy}}, Generation{Revision: 1, Bank: BankA})
	matched, err := MatchNetwork(Bundle{SchemaVersion: SchemaVersion, Policies: []Policy{allowPolicy}}, NetworkObservation{
		Destination: netip.MustParseAddr("192.0.2.10"), Port: 3128, Protocol: ProtocolTCP,
	})
	if err != nil {
		t.Fatalf("MatchNetwork() error = %v", err)
	}

	records, err := engine.EvaluateAuditEvent(events.KernelEvent{
		EventType: events.EventTypeNetConnect, EventTypeName: "net_connect",
		Action: events.ActionBlock, ActionResult: events.ActionResultAllowed,
		PolicyID: stablePolicyID(allowPolicy.ID), RuleID: matched.Hits[0].RuleID, CgroupID: 42,
		DestinationIP: "192.0.2.10", DestinationPort: 3128, Protocol: events.ProtocolTCP,
	})
	if err != nil {
		t.Fatalf("EvaluateAuditEvent() error = %v", err)
	}
	record := records[0].(AuditDecisionRecord)
	if record.Final == nil || record.Final.NetworkDisposition != DispositionAllowed ||
		!record.Final.Enforced || record.Final.EffectiveAction != ActionAudit {
		t.Fatalf("final = %+v", record.Final)
	}
	if len(record.Hits) != 1 || !record.Hits[0].Enforced || record.Hits[0].PostEventOnly ||
		!containsString(record.Hits[0].Reasons, "cgroup_connect_hook_allowed") {
		t.Fatalf("hits = %+v", record.Hits)
	}
}

func TestEvaluateAuditEventRejectsKernelBlockFromAnotherPolicy(t *testing.T) {
	blockPolicy := strictProxyPolicy()
	engine := mustEngine(t, Bundle{SchemaVersion: SchemaVersion, Policies: []Policy{blockPolicy}}, Generation{Revision: 1, Bank: BankA})
	matched, err := MatchNetwork(Bundle{SchemaVersion: SchemaVersion, Policies: []Policy{blockPolicy}}, NetworkObservation{
		Destination: netip.MustParseAddr("198.51.100.8"), Port: 443, Protocol: ProtocolTCP,
	})
	if err != nil {
		t.Fatalf("MatchNetwork() error = %v", err)
	}

	records, err := engine.EvaluateAuditEvent(events.KernelEvent{
		EventType: events.EventTypeNetConnect, EventTypeName: "net_connect",
		Action: events.ActionBlock, ActionResult: events.ActionResultBlocked,
		PolicyID: stablePolicyID("another-policy"), RuleID: matched.Hits[0].RuleID, CgroupID: 42,
		DestinationIP: "198.51.100.8", DestinationPort: 443, Protocol: events.ProtocolTCP,
	})
	if err != nil {
		t.Fatalf("EvaluateAuditEvent() error = %v", err)
	}
	record := records[0].(AuditDecisionRecord)
	if record.Final == nil || record.Final.Enforced || record.Final.EffectiveAction != ActionAudit {
		t.Fatalf("final = %+v, want unmatched post-event decision", record.Final)
	}
	if len(record.Hits) != 1 || record.Hits[0].Enforced ||
		!containsString(record.Hits[0].Reasons, "enforcement_not_connected") {
		t.Fatalf("hits = %+v", record.Hits)
	}
}

func TestEvaluateAuditEventRejectsStaleBlockAfterActionChanges(t *testing.T) {
	containPolicy := strictProxyPolicy()
	containPolicy.RequestedAction = ActionContain
	engine := mustEngine(t, Bundle{SchemaVersion: SchemaVersion, Policies: []Policy{containPolicy}}, Generation{Revision: 2, Bank: BankB})
	matched, err := MatchNetwork(Bundle{SchemaVersion: SchemaVersion, Policies: []Policy{containPolicy}}, NetworkObservation{
		Destination: netip.MustParseAddr("198.51.100.8"), Port: 443, Protocol: ProtocolTCP,
	})
	if err != nil {
		t.Fatalf("MatchNetwork() error = %v", err)
	}

	records, err := engine.EvaluateAuditEvent(events.KernelEvent{
		EventType: events.EventTypeNetConnect, EventTypeName: "net_connect",
		Action: events.ActionBlock, ActionResult: events.ActionResultBlocked,
		PolicyID: stablePolicyID(containPolicy.ID), RuleID: matched.Hits[0].RuleID, CgroupID: 42,
		DestinationIP: "198.51.100.8", DestinationPort: 443, Protocol: events.ProtocolTCP,
	})
	if err != nil {
		t.Fatalf("EvaluateAuditEvent() error = %v", err)
	}
	record := records[0].(AuditDecisionRecord)
	if record.Final == nil || record.Final.Enforced || record.Final.RequestedAction != ActionContain ||
		record.Final.EffectiveAction != ActionAudit || len(record.Hits) != 1 || !record.Hits[0].ContainmentHint {
		t.Fatalf("stale block decision = %+v", record)
	}
}

func TestEvaluateAuditEventMatchesExecAndIgnoresOtherRecords(t *testing.T) {
	execPolicy := filePolicy("exec", Scope{Type: ScopeGlobal}, 1, "/unused")
	execPolicy.Conditions = Conditions{Exec: &ExecCondition{Executables: []string{"bash"}}}
	engine := mustEngine(t, Bundle{SchemaVersion: SchemaVersion, Policies: []Policy{execPolicy}}, Generation{Revision: 1, Bank: BankB})

	records, err := engine.EvaluateAuditEvent(events.KernelEvent{
		EventType: events.EventTypeExecAttempt, EventTypeName: "exec_attempt",
		CgroupID: 42, Data: "/usr/bin/bash", Argv: []string{"bash"},
	})
	if err != nil {
		t.Fatalf("EvaluateAuditEvent() error = %v", err)
	}
	record := records[0].(AuditDecisionRecord)
	if record.Final == nil || record.Final.PolicyID != "exec" {
		t.Fatalf("final = %+v", record.Final)
	}

	records, err = engine.EvaluateAuditEvent(events.KernelEvent{EventType: events.EventTypeDropNotice})
	if err != nil || len(records) != 0 {
		t.Fatalf("drop records = %+v, error = %v", records, err)
	}
}

func TestEvaluateAuditEventDoesNotTreatArgumentTruncationAsExecutableTruncation(t *testing.T) {
	execPolicy := filePolicy("exec", Scope{Type: ScopeGlobal}, 1, "/unused")
	execPolicy.Conditions = Conditions{Exec: &ExecCondition{Executables: []string{"bash"}}}
	engine := mustEngine(t, Bundle{SchemaVersion: SchemaVersion, Policies: []Policy{execPolicy}}, Generation{Revision: 1, Bank: BankA})

	records, err := engine.EvaluateAuditEvent(events.KernelEvent{
		EventType: events.EventTypeExecAttempt, CgroupID: 42,
		Data: "/usr/bin/bash", Argv: []string{"bash", "long-prefix"},
		Truncated: true, ArgumentsTruncated: true,
	})
	if err != nil {
		t.Fatalf("EvaluateAuditEvent() error = %v", err)
	}
	record := records[0].(AuditDecisionRecord)
	if record.Final == nil || record.Final.PolicyID != "exec" {
		t.Fatalf("final = %+v, want executable match despite argument truncation", record.Final)
	}
}

func TestEvaluateAuditEventReportsOPathGapWithoutReadHit(t *testing.T) {
	engine := mustEngine(t, Bundle{SchemaVersion: SchemaVersion, Policies: []Policy{
		filePolicy("read", Scope{Type: ScopeGlobal}, 1, "/shared"),
	}}, Generation{Revision: 1, Bank: BankA})

	records, err := engine.EvaluateAuditEvent(events.KernelEvent{
		EventType: events.EventTypeFileOpen, CgroupID: 1, Data: "/shared", SyscallFlags: openPath,
	})
	if err != nil {
		t.Fatalf("EvaluateAuditEvent() error = %v", err)
	}
	record := records[0].(AuditDecisionRecord)
	if len(record.Hits) != 0 || !hasGap(record.Gaps, "open_path_not_content_access") {
		t.Fatalf("record = %+v", record)
	}
}

func TestEvaluateAuditEventReportsUnavailableFilePathWithoutFailing(t *testing.T) {
	engine := mustEngine(t, Bundle{SchemaVersion: SchemaVersion, Policies: []Policy{
		filePolicy("read", Scope{Type: ScopeGlobal}, 1, "/shared"),
	}}, Generation{Revision: 1, Bank: BankA})

	records, err := engine.EvaluateAuditEvent(events.KernelEvent{
		EventType: events.EventTypeFileOpen, CgroupID: 1, Data: "", Truncated: true,
	})
	if err != nil {
		t.Fatalf("EvaluateAuditEvent() error = %v", err)
	}
	record := records[0].(AuditDecisionRecord)
	if len(record.Hits) != 0 || !hasGap(record.Gaps, "user_path_unavailable") {
		t.Fatalf("record = %+v", record)
	}
}
