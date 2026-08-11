package api

import (
	"context"
	"errors"
	"fmt"
	"strconv"

	"github.com/agentshield/agentshield-ebpf/internal/events"
	"github.com/agentshield/agentshield-ebpf/internal/killer"
	"github.com/agentshield/agentshield-ebpf/internal/policy"
)

var ErrPolicyEventNotActiveRun = errors.New("policy event does not belong to an active Run")

// ContainmentExecutor is the narrow post-event action required by the policy
// coordinator. The concrete killer.Executor retains the scope lifecycle lock
// while it revalidates and acts on the exact cgroup identity.
type ContainmentExecutor interface {
	Contain(context.Context, killer.Request) (killer.Outcome, error)
}

// PolicyContainmentRecord binds an independent containment result to the
// policy decision that requested it. The embedded outcome keeps syscall and
// containment results orthogonal.
type PolicyContainmentRecord struct {
	killer.Outcome
	RunID           string            `json:"run_id"`
	Generation      policy.Generation `json:"generation"`
	PolicyID        string            `json:"policy_id"`
	RuleID          uint32            `json:"rule_id"`
	EventType       uint16            `json:"event_type"`
	EventTypeName   string            `json:"event_type_name"`
	PolicyDecision  policy.Decision   `json:"policy_decision"`
	RequestedAction policy.Action     `json:"requested_action"`
}

// PolicyCoordinator evaluates events only after exact active-Run attribution.
// ProcessAuditEvent may perform cgroup filesystem I/O and must be called from a
// bounded worker outside the ring-buffer reader.
type PolicyCoordinator struct {
	runs        *RunStore
	engine      *policy.Engine
	containment ContainmentExecutor
}

func NewPolicyCoordinator(runs *RunStore, engine *policy.Engine, containment ContainmentExecutor) (*PolicyCoordinator, error) {
	if runs == nil || engine == nil || containment == nil {
		return nil, errors.New("Run store, policy engine, and containment executor are required")
	}
	return &PolicyCoordinator{runs: runs, engine: engine, containment: containment}, nil
}

// ProcessAuditEvent returns a policy_decision followed, when requested by the
// final winning hit, by a correlated containment_result. Execution failures
// are represented by that result record rather than returned as derivation
// errors, so the decision and failure evidence are not discarded.
func (coordinator *PolicyCoordinator) ProcessAuditEvent(ctx context.Context, event events.KernelEvent) ([]any, error) {
	if coordinator == nil {
		return nil, errors.New("policy coordinator is required")
	}
	if ctx == nil {
		return nil, errors.New("policy coordinator context is required")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	run, ok := coordinator.runs.activeRunForPolicyEvent(event.CgroupID, event.InstanceID, event.ScopeCookie)
	if !ok {
		return nil, fmt.Errorf(
			"%w: cgroup=%d instance=%d scope_cookie=%d",
			ErrPolicyEventNotActiveRun,
			event.CgroupID,
			event.InstanceID,
			event.ScopeCookie,
		)
	}

	decision, matched, err := coordinator.engine.EvaluateAuditDecision(policy.EvaluationContext{
		RunID:    run.RunID,
		CgroupID: strconv.FormatUint(run.CgroupID, 10),
		Labels:   run.Labels,
	}, event)
	if err != nil {
		return nil, err
	}
	if !matched {
		return nil, nil
	}

	records := []any{decision}
	hitIndex, execute := containmentWinner(decision, event)
	if !execute {
		return records, nil
	}
	request := killer.Request{
		KernelMonotonicNS: event.KernelMonotonicNS,
		CgroupID:          event.CgroupID,
		InstanceID:        event.InstanceID,
		ScopeCookie:       event.ScopeCookie,
		PID:               event.PID,
		TGID:              event.TGID,
		SyscallResult:     killer.SyscallNotObserved,
	}
	outcome, containmentErr := coordinator.containment.Contain(ctx, request)
	outcome = validatedContainmentOutcome(request, outcome, containmentErr)

	markContainmentResult(&decision, hitIndex, outcome.EnforcementResult)
	final := decision.Final
	records[0] = decision
	records = append(records, PolicyContainmentRecord{
		Outcome:         outcome,
		RunID:           run.RunID,
		Generation:      decision.Generation,
		PolicyID:        final.PolicyID,
		RuleID:          final.RuleID,
		EventType:       event.EventType,
		EventTypeName:   event.EventTypeName,
		PolicyDecision:  final.Decision,
		RequestedAction: final.RequestedAction,
	})
	return records, nil
}

func validatedContainmentOutcome(request killer.Request, outcome killer.Outcome, executionErr error) killer.Outcome {
	contractErr := containmentOutcomeContractError(request, outcome, executionErr)
	if contractErr != nil {
		reason := contractErr.Error()
		if executionErr != nil {
			reason = errors.Join(contractErr, executionErr).Error()
		}
		return killer.Outcome{
			RecordType:        "containment_result",
			KernelMonotonicNS: request.KernelMonotonicNS,
			CgroupID:          request.CgroupID,
			InstanceID:        request.InstanceID,
			ScopeCookie:       request.ScopeCookie,
			PID:               request.PID,
			TGID:              request.TGID,
			SyscallResult:     request.SyscallResult,
			EnforcementMethod: killer.MethodCgroupKill,
			EnforcementResult: killer.ResultFailed,
			Reason:            reason,
		}
	}
	if executionErr != nil && outcome.Reason == "" {
		outcome.Reason = executionErr.Error()
	}
	return outcome
}

func containmentOutcomeContractError(request killer.Request, outcome killer.Outcome, executionErr error) error {
	if outcome.RecordType != "containment_result" {
		return fmt.Errorf("invalid containment outcome: record_type=%q", outcome.RecordType)
	}
	if outcome.KernelMonotonicNS != request.KernelMonotonicNS ||
		outcome.CgroupID != request.CgroupID || outcome.InstanceID != request.InstanceID ||
		outcome.ScopeCookie != request.ScopeCookie || outcome.PID != request.PID || outcome.TGID != request.TGID {
		return errors.New("invalid containment outcome: event or scope identity does not match the request")
	}
	if outcome.SyscallResult != request.SyscallResult {
		return errors.New("invalid containment outcome: syscall result does not match the request")
	}
	if outcome.EnforcementMethod != killer.MethodCgroupKill {
		return fmt.Errorf("invalid containment outcome: enforcement method=%q", outcome.EnforcementMethod)
	}
	switch outcome.EnforcementResult {
	case killer.ResultNotAttempted, killer.ResultKilled, killer.ResultFailed:
	default:
		return fmt.Errorf("invalid containment outcome: enforcement result=%q", outcome.EnforcementResult)
	}
	if executionErr != nil && outcome.EnforcementResult == killer.ResultKilled {
		return errors.New("invalid containment outcome: killed result returned with an execution error")
	}
	if executionErr == nil && outcome.EnforcementResult != killer.ResultKilled && outcome.Reason == "" {
		return errors.New("invalid containment outcome: non-success result has no reason")
	}
	return nil
}

func (store *RunStore) activeRunForPolicyEvent(cgroupID, instanceID, scopeCookie uint64) (AgentRun, bool) {
	if store == nil || cgroupID == 0 || instanceID == 0 || scopeCookie == 0 {
		return AgentRun{}, false
	}
	identity := ScopeIdentity{InstanceID: instanceID, ScopeCookie: scopeCookie}
	store.mu.RLock()
	defer store.mu.RUnlock()
	runID, exists := store.liveByIdentity[identity]
	if !exists {
		return AgentRun{}, false
	}
	if _, terminating := store.terminating[runID]; terminating {
		return AgentRun{}, false
	}
	run, exists := store.runs[runID]
	if !exists || run.Status != "active" || run.CgroupID != cgroupID || run.scopeIdentity() != identity {
		return AgentRun{}, false
	}
	run.Labels = cloneLabels(run.Labels)
	return run, true
}

func containmentWinner(decision policy.AuditDecisionRecord, event events.KernelEvent) (int, bool) {
	final := decision.Final
	if final == nil || final.Decision != policy.DecisionDeny || final.RequestedAction != policy.ActionContain || final.Enforced {
		return 0, false
	}
	if event.ActionResult == events.ActionResultBlocked {
		return 0, false
	}
	if event.EventType == events.EventTypeNetConnect && final.NetworkDisposition != policy.DispositionDenied {
		return 0, false
	}
	winner := -1
	for index := range decision.Hits {
		hit := decision.Hits[index]
		if hit.PolicyID != final.PolicyID || hit.RuleID != final.RuleID {
			continue
		}
		if winner != -1 {
			return 0, false
		}
		winner = index
	}
	if winner == -1 || !decision.Hits[winner].ContainmentHint {
		return 0, false
	}
	return winner, true
}

func markContainmentResult(decision *policy.AuditDecisionRecord, hitIndex int, result killer.EnforcementResult) {
	hit := &decision.Hits[hitIndex]
	switch result {
	case killer.ResultKilled:
		hit.EffectiveAction = policy.ActionContain
		hit.Enforced = true
		hit.ContainmentHint = false
		hit.Reasons = removePolicyReason(hit.Reasons, "containment_not_executed")
		if decision.EventType == events.EventTypeNetConnect {
			hit.Reasons = removePolicyReason(hit.Reasons, "enforcement_not_connected")
			hit.Reasons = appendPolicyReason(hit.Reasons, "synchronous_enforcement_not_connected")
		}
		hit.Reasons = appendPolicyReason(hit.Reasons, "post_event_containment_killed")
		decision.Final.EffectiveAction = policy.ActionContain
		decision.Final.Enforced = true
	case killer.ResultFailed:
		hit.Reasons = appendPolicyReason(hit.Reasons, "post_event_containment_failed")
	default:
		hit.Reasons = appendPolicyReason(hit.Reasons, "post_event_containment_not_attempted")
	}
}

func removePolicyReason(reasons []string, remove string) []string {
	filtered := reasons[:0]
	for _, reason := range reasons {
		if reason != remove {
			filtered = append(filtered, reason)
		}
	}
	return filtered
}

func appendPolicyReason(reasons []string, value string) []string {
	for _, reason := range reasons {
		if reason == value {
			return reasons
		}
	}
	return append(reasons, value)
}
