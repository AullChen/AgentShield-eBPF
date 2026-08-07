package policy

import (
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
