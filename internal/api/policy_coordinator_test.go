package api

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"testing"

	"github.com/agentshield/agentshield-ebpf/internal/events"
	"github.com/agentshield/agentshield-ebpf/internal/killer"
	"github.com/agentshield/agentshield-ebpf/internal/policy"
)

func TestP3Acceptance(t *testing.T) {
	coordinator, containment, bundle, run := newP3Coordinator(t, killer.ResultKilled, nil, p3Policies()...)

	t.Run("audit", func(t *testing.T) {
		containment.reset()
		records, err := coordinator.ProcessAuditEvent(context.Background(), p3ExecEvent(run, "audit-tool"))
		if err != nil {
			t.Fatalf("ProcessAuditEvent: %v", err)
		}
		decision := onlyP3Decision(t, records)
		if decision.Final == nil || decision.Final.RequestedAction != policy.ActionAudit ||
			decision.Final.EffectiveAction != policy.ActionAudit || decision.Final.Enforced {
			t.Fatalf("audit final = %+v", decision.Final)
		}
		if len(containment.calls) != 0 {
			t.Fatalf("audit containment calls = %d", len(containment.calls))
		}
	})

	t.Run("alert", func(t *testing.T) {
		containment.reset()
		records, err := coordinator.ProcessAuditEvent(context.Background(), p3ExecEvent(run, "alert-tool"))
		if err != nil {
			t.Fatalf("ProcessAuditEvent: %v", err)
		}
		decision := onlyP3Decision(t, records)
		if decision.Final == nil || decision.Final.RequestedAction != policy.ActionAlert ||
			decision.Final.EffectiveAction != policy.ActionAlert || decision.Final.Enforced {
			t.Fatalf("alert final = %+v", decision.Final)
		}
		if len(containment.calls) != 0 {
			t.Fatalf("alert containment calls = %d", len(containment.calls))
		}
	})

	t.Run("synchronous_block", func(t *testing.T) {
		containment.reset()
		generation := policy.Generation{Revision: 7, Bank: policy.BankA}
		image, err := policy.CompileNetworkEnforcement(
			bundle,
			policy.EvaluationContext{RunID: run.RunID, CgroupID: "42", Labels: run.Labels},
			9,
			generation,
		)
		if err != nil {
			t.Fatalf("CompileNetworkEnforcement: %v", err)
		}
		event := p3Event(run)
		event.EventType = events.EventTypeNetConnect
		event.EventTypeName = "net_connect"
		event.Action = events.ActionBlock
		event.ActionResult = events.ActionResultBlocked
		event.PolicyID = image.PolicyID
		event.RuleID = image.RuleID
		event.DestinationIP = "198.51.100.8"
		event.DestinationPort = 443
		event.Protocol = events.ProtocolTCP

		records, err := coordinator.ProcessAuditEvent(context.Background(), event)
		if err != nil {
			t.Fatalf("ProcessAuditEvent: %v", err)
		}
		decision := onlyP3Decision(t, records)
		if decision.Final == nil || decision.Final.EffectiveAction != policy.ActionBlock || !decision.Final.Enforced ||
			len(decision.Hits) != 1 || !hasP3Reason(decision.Hits[0].Reasons, "cgroup_connect_hook_blocked") {
			t.Fatalf("block decision = %+v", decision)
		}
		if len(containment.calls) != 0 {
			t.Fatalf("block containment calls = %d", len(containment.calls))
		}
	})

	t.Run("post_event_containment", func(t *testing.T) {
		containment.reset()
		event := p3ExecEvent(run, "contain-tool")
		records, err := coordinator.ProcessAuditEvent(context.Background(), event)
		if err != nil {
			t.Fatalf("ProcessAuditEvent: %v", err)
		}
		if len(records) != 2 {
			t.Fatalf("record count = %d, want decision and containment result", len(records))
		}
		decision := records[0].(policy.AuditDecisionRecord)
		if decision.Final == nil || decision.Final.EffectiveAction != policy.ActionContain || !decision.Final.Enforced ||
			len(decision.Hits) != 1 || decision.Hits[0].ContainmentHint ||
			!hasP3Reason(decision.Hits[0].Reasons, "post_event_containment_killed") {
			t.Fatalf("contain decision = %+v", decision)
		}
		result := records[1].(PolicyContainmentRecord)
		if result.RunID != run.RunID || result.PolicyID != decision.Final.PolicyID ||
			result.RuleID != decision.Final.RuleID || result.EnforcementMethod != killer.MethodCgroupKill ||
			result.EnforcementResult != killer.ResultKilled || result.SyscallResult != killer.SyscallNotObserved {
			t.Fatalf("containment result = %+v", result)
		}
		if event.ActionResult != events.ActionResultNone || len(containment.calls) != 1 {
			t.Fatalf("raw action result = %d, containment calls = %d", event.ActionResult, len(containment.calls))
		}
	})
}

func TestPolicyCoordinatorRejectsUntrustedAndTerminatingRuns(t *testing.T) {
	for _, mutate := range []func(*events.KernelEvent){
		func(event *events.KernelEvent) { event.CgroupID++ },
		func(event *events.KernelEvent) { event.InstanceID++ },
		func(event *events.KernelEvent) { event.ScopeCookie++ },
	} {
		coordinator, containment, _, run := newP3Coordinator(t, killer.ResultKilled, nil, p3Policies()...)
		event := p3ExecEvent(run, "contain-tool")
		mutate(&event)
		if _, err := coordinator.ProcessAuditEvent(context.Background(), event); !errors.Is(err, ErrPolicyEventNotActiveRun) {
			t.Fatalf("stale identity error = %v", err)
		}
		if len(containment.calls) != 0 {
			t.Fatalf("stale identity containment calls = %d", len(containment.calls))
		}
	}

	coordinator, _, _, run := newP3Coordinator(t, killer.ResultKilled, nil, p3Policies()...)
	if _, begun, err := coordinator.runs.beginTermination(run.RunID); err != nil || !begun {
		t.Fatalf("beginTermination: begun=%v error=%v", begun, err)
	}
	if _, err := coordinator.ProcessAuditEvent(context.Background(), p3ExecEvent(run, "contain-tool")); !errors.Is(err, ErrPolicyEventNotActiveRun) {
		t.Fatalf("terminating Run error = %v", err)
	}

	coordinator, _, _, run = newP3Coordinator(t, killer.ResultKilled, nil, p3Policies()...)
	if _, changed, found := coordinator.runs.FailScope(run.CgroupID, "scope escaped"); !found || !changed {
		t.Fatalf("FailScope: found=%v changed=%v", found, changed)
	}
	if _, err := coordinator.ProcessAuditEvent(context.Background(), p3ExecEvent(run, "contain-tool")); !errors.Is(err, ErrPolicyEventNotActiveRun) {
		t.Fatalf("failed Run error = %v", err)
	}
}

func TestPolicyCoordinatorRecordsContainmentFailure(t *testing.T) {
	executionErr := errors.New("cgroup.kill unavailable")
	coordinator, containment, _, run := newP3Coordinator(t, killer.ResultFailed, executionErr, p3Policies()...)
	records, err := coordinator.ProcessAuditEvent(context.Background(), p3ExecEvent(run, "contain-tool"))
	if err != nil {
		t.Fatalf("ProcessAuditEvent returned execution error instead of records: %v", err)
	}
	if len(records) != 2 || len(containment.calls) != 1 {
		t.Fatalf("records=%d calls=%d", len(records), len(containment.calls))
	}
	decision := records[0].(policy.AuditDecisionRecord)
	if decision.Final == nil || decision.Final.Enforced || decision.Final.EffectiveAction != policy.ActionAlert ||
		!decision.Hits[0].ContainmentHint || !hasP3Reason(decision.Hits[0].Reasons, "post_event_containment_failed") {
		t.Fatalf("failed contain decision = %+v", decision)
	}
	result := records[1].(PolicyContainmentRecord)
	if result.EnforcementResult != killer.ResultFailed || result.Reason != executionErr.Error() {
		t.Fatalf("failed containment result = %+v", result)
	}
}

func TestPolicyCoordinatorRejectsInconsistentContainmentOutcome(t *testing.T) {
	tests := []struct {
		name       string
		result     killer.EnforcementResult
		executeErr error
		mutate     func(*killer.Outcome)
	}{
		{name: "killed with error", result: killer.ResultKilled, executeErr: errors.New("late executor failure")},
		{name: "mismatched identity", result: killer.ResultKilled, mutate: func(outcome *killer.Outcome) { outcome.ScopeCookie++ }},
		{name: "unexplained failure", result: killer.ResultFailed},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			coordinator, containment, _, run := newP3Coordinator(t, test.result, test.executeErr, p3Policies()...)
			containment.mutate = test.mutate
			records, err := coordinator.ProcessAuditEvent(context.Background(), p3ExecEvent(run, "contain-tool"))
			if err != nil {
				t.Fatalf("ProcessAuditEvent: %v", err)
			}
			decision := records[0].(policy.AuditDecisionRecord)
			result := records[1].(PolicyContainmentRecord)
			if decision.Final == nil || decision.Final.Enforced || decision.Final.EffectiveAction != policy.ActionAlert {
				t.Fatalf("inconsistent outcome decision = %+v", decision)
			}
			if result.EnforcementResult != killer.ResultFailed ||
				!strings.Contains(result.Reason, "invalid containment outcome") || result.ScopeCookie != run.ScopeCookie {
				t.Fatalf("normalized containment result = %+v", result)
			}
		})
	}
}

func TestPolicyCoordinatorDoesNotExecuteNonWinningOrAllowedContainment(t *testing.T) {
	contain := p3ExecPolicy("p3.contain", "shared-tool", policy.DecisionDeny, policy.ActionContain, 10)
	alert := p3ExecPolicy("p3.alert", "shared-tool", policy.DecisionObserve, policy.ActionAlert, 100)
	coordinator, containment, _, run := newP3Coordinator(t, killer.ResultKilled, nil, contain, alert)
	records, err := coordinator.ProcessAuditEvent(context.Background(), p3ExecEvent(run, "shared-tool"))
	if err != nil {
		t.Fatalf("ProcessAuditEvent: %v", err)
	}
	decision := onlyP3Decision(t, records)
	if decision.Final == nil || decision.Final.PolicyID != alert.ID || len(containment.calls) != 0 {
		t.Fatalf("non-winning contain decision = %+v calls=%d", decision, len(containment.calls))
	}

	allowlistedContain := p3NetworkPolicy("p3.net.contain", policy.ActionContain)
	coordinator, containment, _, run = newP3Coordinator(t, killer.ResultKilled, nil, allowlistedContain)
	event := p3Event(run)
	event.EventType = events.EventTypeNetConnect
	event.EventTypeName = "net_connect"
	event.DestinationIP = netip.MustParseAddr("192.0.2.10").String()
	event.DestinationPort = 3128
	event.Protocol = events.ProtocolTCP
	records, err = coordinator.ProcessAuditEvent(context.Background(), event)
	if err != nil {
		t.Fatalf("ProcessAuditEvent allowlisted contain: %v", err)
	}
	decision = onlyP3Decision(t, records)
	if decision.Final == nil || decision.Final.NetworkDisposition != policy.DispositionAllowed ||
		decision.Hits[0].ContainmentHint || len(containment.calls) != 0 {
		t.Fatalf("allowlisted contain decision = %+v calls=%d", decision, len(containment.calls))
	}

	coordinator, containment, _, run = newP3Coordinator(
		t,
		killer.ResultKilled,
		nil,
		p3ExecPolicy("p3.contain", "blocked-tool", policy.DecisionDeny, policy.ActionContain, 10),
	)
	blockedEvent := p3ExecEvent(run, "blocked-tool")
	blockedEvent.ActionResult = events.ActionResultBlocked
	records, err = coordinator.ProcessAuditEvent(context.Background(), blockedEvent)
	if err != nil {
		t.Fatalf("ProcessAuditEvent already blocked: %v", err)
	}
	decision = onlyP3Decision(t, records)
	if decision.Final == nil || !decision.Hits[0].ContainmentHint || len(containment.calls) != 0 {
		t.Fatalf("already-blocked contain decision = %+v calls=%d", decision, len(containment.calls))
	}
}

func TestPolicyCoordinatorKeepsNetworkSyscallSeparateFromContainment(t *testing.T) {
	tests := []struct {
		name             string
		result           killer.EnforcementResult
		executionErr     error
		effectiveAction  policy.Action
		enforced         bool
		expectedReason   string
		unexpectedReason string
	}{
		{
			name: "killed", result: killer.ResultKilled,
			effectiveAction: policy.ActionContain, enforced: true,
			expectedReason: "synchronous_enforcement_not_connected", unexpectedReason: "enforcement_not_connected",
		},
		{
			name: "failed", result: killer.ResultFailed, executionErr: errors.New("cgroup.kill failed"),
			effectiveAction: policy.ActionAudit, enforced: false,
			expectedReason: "post_event_containment_failed",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			coordinator, containment, _, run := newP3Coordinator(
				t,
				test.result,
				test.executionErr,
				p3NetworkPolicy("p3.net.contain", policy.ActionContain),
			)
			event := p3Event(run)
			event.EventType = events.EventTypeNetConnect
			event.EventTypeName = "net_connect"
			event.DestinationIP = "198.51.100.8"
			event.DestinationPort = 443
			event.Protocol = events.ProtocolTCP

			records, err := coordinator.ProcessAuditEvent(context.Background(), event)
			if err != nil {
				t.Fatalf("ProcessAuditEvent: %v", err)
			}
			if len(records) != 2 || len(containment.calls) != 1 {
				t.Fatalf("records=%d calls=%d", len(records), len(containment.calls))
			}
			decision := records[0].(policy.AuditDecisionRecord)
			result := records[1].(PolicyContainmentRecord)
			if decision.Final == nil || decision.Final.NetworkDisposition != policy.DispositionDenied ||
				decision.Final.EffectiveAction != test.effectiveAction || decision.Final.Enforced != test.enforced ||
				len(decision.NetworkDecisions) != 1 || decision.NetworkDecisions[0].Enforced ||
				!hasP3Reason(decision.Hits[0].Reasons, test.expectedReason) ||
				(test.unexpectedReason != "" && hasP3Reason(decision.Hits[0].Reasons, test.unexpectedReason)) {
				t.Fatalf("network containment decision = %+v", decision)
			}
			if event.ActionResult != events.ActionResultNone || result.SyscallResult != killer.SyscallNotObserved ||
				result.EnforcementResult != test.result {
				t.Fatalf("event action result=%d containment=%+v", event.ActionResult, result)
			}
		})
	}
}

type fakeContainmentExecutor struct {
	result killer.EnforcementResult
	err    error
	calls  []killer.Request
	mutate func(*killer.Outcome)
}

func (executor *fakeContainmentExecutor) Contain(_ context.Context, request killer.Request) (killer.Outcome, error) {
	executor.calls = append(executor.calls, request)
	outcome := killer.Outcome{
		RecordType:        "containment_result",
		KernelMonotonicNS: request.KernelMonotonicNS,
		CgroupID:          request.CgroupID,
		InstanceID:        request.InstanceID,
		ScopeCookie:       request.ScopeCookie,
		PID:               request.PID,
		TGID:              request.TGID,
		SyscallResult:     request.SyscallResult,
		EnforcementMethod: killer.MethodCgroupKill,
		EnforcementResult: executor.result,
	}
	if executor.mutate != nil {
		executor.mutate(&outcome)
	}
	return outcome, executor.err
}

func (executor *fakeContainmentExecutor) reset() {
	executor.calls = nil
}

func newP3Coordinator(t *testing.T, result killer.EnforcementResult, executionErr error, policies ...policy.Policy) (*PolicyCoordinator, *fakeContainmentExecutor, policy.Bundle, AgentRun) {
	t.Helper()
	run := AgentRun{
		RunID: "run-p3", CgroupID: 42, InstanceID: 1001, ScopeCookie: 2002,
		Labels: map[string]string{"environment": "acceptance"}, Status: "active",
	}
	runs := NewRunStore()
	if err := runs.Add(run); err != nil {
		t.Fatalf("RunStore.Add: %v", err)
	}
	bundle := policy.Bundle{SchemaVersion: policy.SchemaVersion, Policies: policies}
	engine, _, err := policy.NewEngine(bundle, policy.Generation{Revision: 7, Bank: policy.BankA}, policy.Limits{})
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	containment := &fakeContainmentExecutor{result: result, err: executionErr}
	coordinator, err := NewPolicyCoordinator(runs, engine, containment)
	if err != nil {
		t.Fatalf("NewPolicyCoordinator: %v", err)
	}
	return coordinator, containment, bundle, run
}

func p3Policies() []policy.Policy {
	return []policy.Policy{
		p3ExecPolicy("p3.audit", "audit-tool", policy.DecisionObserve, policy.ActionAudit, 10),
		p3ExecPolicy("p3.alert", "alert-tool", policy.DecisionObserve, policy.ActionAlert, 20),
		p3ExecPolicy("p3.contain", "contain-tool", policy.DecisionDeny, policy.ActionContain, 30),
		p3NetworkPolicy("p3.block", policy.ActionBlock),
	}
}

func p3ExecPolicy(id, executable string, decision policy.Decision, action policy.Action, priority int) policy.Policy {
	return policy.Policy{
		ID: id, Name: id, Enabled: true,
		Scope:           policy.Scope{Type: policy.ScopeRun, RunID: "run-p3"},
		Decision:        decision,
		RequestedAction: action,
		Priority:        priority,
		Severity:        policy.SeverityHigh,
		Conditions: policy.Conditions{Exec: &policy.ExecCondition{
			Executables: []string{executable},
		}},
	}
}

func p3NetworkPolicy(id string, action policy.Action) policy.Policy {
	return policy.Policy{
		ID: id, Name: id, Enabled: true,
		Scope:           policy.Scope{Type: policy.ScopeRun, RunID: "run-p3"},
		Decision:        policy.DecisionDeny,
		RequestedAction: action,
		Priority:        40,
		Severity:        policy.SeverityHigh,
		Conditions: policy.Conditions{Network: &policy.NetworkCondition{
			Default:  policy.NetworkDefaultDeny,
			CIDRs:    []string{"192.0.2.10/32"},
			Ports:    []policy.PortRange{{From: 3128, To: 3128}},
			Families: []policy.IPFamily{policy.FamilyIPv4},
		}},
	}
}

func p3Event(run AgentRun) events.KernelEvent {
	return events.KernelEvent{
		KernelMonotonicNS: 500,
		CgroupID:          run.CgroupID,
		InstanceID:        run.InstanceID,
		ScopeCookie:       run.ScopeCookie,
		PID:               123,
		TGID:              123,
	}
}

func p3ExecEvent(run AgentRun, executable string) events.KernelEvent {
	event := p3Event(run)
	event.EventType = events.EventTypeExecAttempt
	event.EventTypeName = "exec_attempt"
	event.Data = "/usr/bin/" + executable
	event.Argv = []string{executable}
	return event
}

func onlyP3Decision(t *testing.T, records []any) policy.AuditDecisionRecord {
	t.Helper()
	if len(records) != 1 {
		t.Fatalf("record count = %d, want one policy decision", len(records))
	}
	decision, ok := records[0].(policy.AuditDecisionRecord)
	if !ok {
		t.Fatalf("record type = %T, want policy.AuditDecisionRecord", records[0])
	}
	if decision.RecordType != "policy_decision" || decision.RunID != "run-p3" {
		t.Fatalf("decision identity = %+v", decision)
	}
	return decision
}

func hasP3Reason(reasons []string, expected string) bool {
	for _, reason := range reasons {
		if reason == expected {
			return true
		}
	}
	return false
}
