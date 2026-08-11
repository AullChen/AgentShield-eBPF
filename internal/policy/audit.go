package policy

import (
	"fmt"
	"net/netip"
	"strconv"

	"github.com/agentshield/agentshield-ebpf/internal/events"
)

const (
	openAccessMode = uint32(3)
	openWriteOnly  = uint32(1)
	openReadWrite  = uint32(2)
	openPath       = uint32(0x200000)
)

// AuditDecisionRecord correlates a user-space policy evaluation with the raw
// kernel event that immediately precedes it in the JSON Lines audit stream.
type AuditDecisionRecord struct {
	RecordType                string `json:"record_type"`
	RunID                     string `json:"run_id,omitempty"`
	KernelMonotonicNS         uint64 `json:"kernel_monotonic_ns,string"`
	ServerReceivedMonotonicNS uint64 `json:"server_received_monotonic_ns,string,omitempty"`
	CgroupID                  uint64 `json:"cgroup_id,string"`
	InstanceID                uint64 `json:"instance_id,string"`
	ScopeCookie               uint64 `json:"scope_cookie,string"`
	PID                       uint32 `json:"pid"`
	EventType                 uint16 `json:"event_type"`
	EventTypeName             string `json:"event_type_name"`
	DecisionReport
	NetworkDecisions []NetworkPolicyDecision `json:"network_decisions,omitempty"`
}

// EvaluateAuditEvent returns zero records for event types without a policy
// matcher and one correlated decision record for file, exec, and network
// events. The caller can append the result directly after the raw event.
func (engine *Engine) EvaluateAuditEvent(event events.KernelEvent) ([]any, error) {
	record, matched, err := engine.EvaluateAuditDecision(EvaluationContext{}, event)
	if err != nil {
		return nil, err
	}
	if !matched {
		return nil, nil
	}
	return []any{record}, nil
}

// EvaluateAuditDecision evaluates one event with trusted Run metadata supplied
// by an orchestration layer. The event's cgroup identity remains authoritative
// and must agree with an explicitly supplied cgroup context.
func (engine *Engine) EvaluateAuditDecision(context EvaluationContext, event events.KernelEvent) (AuditDecisionRecord, bool, error) {
	eventCgroupID := strconv.FormatUint(event.CgroupID, 10)
	if context.CgroupID != "" && context.CgroupID != eventCgroupID {
		return AuditDecisionRecord{}, false, fmt.Errorf(
			"policy context cgroup %q does not match event cgroup %q",
			context.CgroupID,
			eventCgroupID,
		)
	}
	context.CgroupID = eventCgroupID
	var report DecisionReport
	var networkDecisions []NetworkPolicyDecision

	switch event.EventType {
	case events.EventTypeFileOpen:
		fileReport, err := engine.evaluateFileAuditEvent(context, event)
		if err != nil {
			return AuditDecisionRecord{}, false, err
		}
		report = fileReport
	case events.EventTypeExecAttempt:
		executableTruncated := event.ExecutableTruncated
		argumentsTruncated := event.ArgumentsTruncated
		if event.Truncated && !executableTruncated && !argumentsTruncated {
			// Preserve conservative behavior for legacy JSON/wire-v3 events that
			// only carry the aggregate truncation flag.
			executableTruncated = true
			argumentsTruncated = true
		}
		argumentsState := CaptureComplete
		arguments := event.Argv
		if event.FieldsUnavailable {
			argumentsState = CaptureUnavailable
			arguments = nil
		} else if argumentsTruncated {
			argumentsState = CaptureTruncated
		}
		execReport, err := engine.EvaluateExec(context, ExecObservation{
			Operation:           ExecOperationExecve,
			Executable:          event.Data,
			ExecutableTruncated: executableTruncated,
			Arguments:           arguments,
			ArgumentsState:      argumentsState,
		})
		if err != nil {
			return AuditDecisionRecord{}, false, err
		}
		report = execReport
	case events.EventTypeNetConnect:
		destination, err := netip.ParseAddr(event.DestinationIP)
		if err != nil {
			return AuditDecisionRecord{}, false, fmt.Errorf("parse audit destination %q: %w", event.DestinationIP, err)
		}
		protocol := NetworkProtocol("")
		if event.Protocol == events.ProtocolTCP {
			protocol = ProtocolTCP
		}
		networkReport, err := engine.EvaluateNetwork(context, NetworkObservation{
			Destination: destination,
			Port:        event.DestinationPort,
			Protocol:    protocol,
		})
		if err != nil {
			return AuditDecisionRecord{}, false, err
		}
		reconcileNetworkEnforcement(&networkReport, event)
		report = networkReport.DecisionReport
		networkDecisions = networkReport.Decisions
	default:
		return AuditDecisionRecord{}, false, nil
	}

	record := AuditDecisionRecord{
		RecordType:                "policy_decision",
		RunID:                     context.RunID,
		KernelMonotonicNS:         event.KernelMonotonicNS,
		ServerReceivedMonotonicNS: event.ServerReceivedMonotonicNS,
		CgroupID:                  event.CgroupID,
		InstanceID:                event.InstanceID,
		ScopeCookie:               event.ScopeCookie,
		PID:                       event.PID,
		EventType:                 event.EventType,
		EventTypeName:             event.EventTypeName,
		DecisionReport:            report,
		NetworkDecisions:          networkDecisions,
	}
	return record, true, nil
}

func reconcileNetworkEnforcement(report *NetworkDecisionReport, event events.KernelEvent) {
	if event.Action != events.ActionBlock || event.PolicyID == 0 || event.RuleID == 0 {
		return
	}
	if report.Final == nil || stablePolicyID(report.Final.PolicyID) != event.PolicyID ||
		report.Final.RuleID != event.RuleID || report.Final.RequestedAction != ActionBlock {
		return
	}
	resultReason := ""
	expectedDisposition := NetworkDisposition("")
	switch event.ActionResult {
	case events.ActionResultBlocked:
		resultReason = "cgroup_connect_hook_blocked"
		expectedDisposition = DispositionDenied
	case events.ActionResultAllowed:
		resultReason = "cgroup_connect_hook_allowed"
		expectedDisposition = DispositionAllowed
	default:
		return
	}
	decisionIndex := -1
	for index := range report.Decisions {
		decision := &report.Decisions[index]
		if stablePolicyID(decision.PolicyID) == event.PolicyID && decision.RuleID == event.RuleID &&
			decision.Disposition == expectedDisposition {
			decisionIndex = index
			break
		}
	}
	if decisionIndex == -1 {
		return
	}
	hitIndex := -1
	for index := range report.Hits {
		hit := &report.Hits[index]
		if stablePolicyID(hit.PolicyID) == event.PolicyID && hit.RuleID == event.RuleID &&
			hit.RequestedAction == ActionBlock {
			hitIndex = index
			break
		}
	}
	if hitIndex == -1 {
		return
	}

	decision := &report.Decisions[decisionIndex]
	decision.Enforced = true
	decision.Reasons = appendWithout(decision.Reasons, resultReason)
	hit := &report.Hits[hitIndex]
	hit.Enforced = true
	hit.PostEventOnly = false
	hit.Reasons = removeReason(hit.Reasons, "enforcement_not_connected")
	hit.Reasons = appendWithout(hit.Reasons, resultReason)
	report.Final.Enforced = true
	if event.ActionResult == events.ActionResultBlocked {
		hit.EffectiveAction = ActionBlock
		report.Final.EffectiveAction = ActionBlock
	}
}

func removeReason(reasons []string, remove string) []string {
	filtered := reasons[:0]
	for _, reason := range reasons {
		if reason != remove {
			filtered = append(filtered, reason)
		}
	}
	return filtered
}

func appendWithout(reasons []string, value string) []string {
	for _, reason := range reasons {
		if reason == value {
			return reasons
		}
	}
	return append(reasons, value)
}

func (engine *Engine) evaluateFileAuditEvent(context EvaluationContext, event events.KernelEvent) (DecisionReport, error) {
	snapshot, err := engine.snapshot()
	if err != nil {
		return DecisionReport{}, err
	}
	if event.SyscallFlags&openPath != 0 {
		report := emptyDecisionReport(snapshot.generation)
		if len(selectPolicies(snapshot.bundle, context, conditionFile).Policies) > 0 {
			report.Gaps = []EvaluationGap{{
				Code: "open_path_not_content_access", Message: "O_PATH does not grant file content access",
			}}
		}
		return report, nil
	}
	if event.Data == "" {
		report := emptyDecisionReport(snapshot.generation)
		if len(selectPolicies(snapshot.bundle, context, conditionFile).Policies) > 0 {
			report.Gaps = []EvaluationGap{{
				Code: "user_path_unavailable", Message: "file pathname was not captured",
			}}
		}
		return report, nil
	}
	accesses := []FileAccess{FileRead}
	switch event.SyscallFlags & openAccessMode {
	case openWriteOnly:
		accesses = []FileAccess{FileWrite}
	case openReadWrite:
		accesses = []FileAccess{FileRead, FileWrite}
	}
	observations := make([]FileObservation, 0, len(accesses))
	for _, access := range accesses {
		observations = append(observations, FileObservation{
			UserPath:          event.Data,
			UserPathTruncated: event.Truncated,
			Access:            access,
		})
	}
	return evaluateFileSnapshot(snapshot, context, observations)
}
