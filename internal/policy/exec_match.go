package policy

import (
	"errors"
	"fmt"
	"path"
	"slices"
	"strings"
)

type ExecOperation string

const (
	ExecOperationExecve   ExecOperation = "execve"
	ExecOperationExecveat ExecOperation = "execveat"
)

type CaptureState string

const (
	CaptureComplete    CaptureState = "complete"
	CaptureTruncated   CaptureState = "truncated"
	CaptureUnavailable CaptureState = "unavailable"
)

type ExecObservation struct {
	Operation           ExecOperation
	Executable          string
	ExecutableTruncated bool
	Arguments           []string
	ArgumentsState      CaptureState
	ExecveatFlags       uint32
}

type compiledExecRule struct {
	policy Policy
	id     uint32
	kind   string
	value  string
}

func MatchExec(bundle Bundle, observation ExecObservation) (MatchResult, error) {
	if err := bundle.Validate(); err != nil {
		return MatchResult{}, fmt.Errorf("validate policy bundle: %w", err)
	}
	if err := validateExecObservation(observation); err != nil {
		return MatchResult{}, err
	}
	rules, err := compileExecRules(bundle)
	if err != nil {
		return MatchResult{}, err
	}
	result := MatchResult{}
	addExecCaptureGaps(observation, &result)
	for _, rule := range rules {
		matched, confidence, reasons := execRuleMatches(rule, observation)
		if !matched {
			continue
		}
		effectiveAction := rule.policy.RequestedAction
		containmentHint := false
		if effectiveAction == ActionContain {
			effectiveAction = ActionAlert
			containmentHint = true
			reasons = append(reasons, "containment_not_executed")
		}
		result.Hits = append(result.Hits, PolicyHit{
			PolicyID:        rule.policy.ID,
			RuleID:          rule.id,
			RuleKind:        rule.kind,
			RequestedAction: rule.policy.RequestedAction,
			EffectiveAction: effectiveAction,
			EvidenceSource:  EvidenceExecCapture,
			Confidence:      confidence,
			PostEventOnly:   true,
			ContainmentHint: containmentHint,
			Reasons:         reasons,
		})
	}
	return result, nil
}

func validateExecObservation(observation ExecObservation) error {
	if observation.Operation != ExecOperationExecve && observation.Operation != ExecOperationExecveat {
		return fmt.Errorf("exec operation %q is not supported", observation.Operation)
	}
	if observation.ArgumentsState != CaptureComplete &&
		observation.ArgumentsState != CaptureTruncated &&
		observation.ArgumentsState != CaptureUnavailable {
		return fmt.Errorf("argument capture state %q is not supported", observation.ArgumentsState)
	}
	if observation.ArgumentsState == CaptureUnavailable && len(observation.Arguments) != 0 {
		return errors.New("unavailable argument capture must not contain arguments")
	}
	return nil
}

func compileExecRules(bundle Bundle) ([]compiledExecRule, error) {
	registry := make(ruleIDRegistry)
	var rules []compiledExecRule
	for _, policy := range bundle.Policies {
		condition := policy.Conditions.Exec
		if !policy.Enabled || condition == nil {
			continue
		}
		if policy.RequestedAction == ActionBlock {
			return nil, fmt.Errorf("exec policy %q requests block; exec capture supports only audit, alert, or containment hint", policy.ID)
		}
		groups := []struct {
			kind   string
			values []string
		}{
			{"exec_executable", condition.Executables},
			{"exec_argument", condition.ArgContains},
		}
		for _, group := range groups {
			for index, value := range group.values {
				ruleID, err := registry.add(policy.ID, group.kind, index)
				if err != nil {
					return nil, err
				}
				rules = append(rules, compiledExecRule{
					policy: policy,
					id:     ruleID,
					kind:   group.kind,
					value:  value,
				})
			}
		}
	}
	return rules, nil
}

func addExecCaptureGaps(observation ExecObservation, result *MatchResult) {
	if observation.Executable == "" {
		result.Gaps = append(result.Gaps, EvaluationGap{
			Code: "executable_unavailable", Message: "executable pathname was not captured",
		})
	}
	if observation.ExecutableTruncated {
		result.Gaps = append(result.Gaps, EvaluationGap{
			Code: "executable_truncated", Message: "executable pathname capture is incomplete",
		})
	}
	switch observation.ArgumentsState {
	case CaptureUnavailable:
		result.Gaps = append(result.Gaps, EvaluationGap{
			Code: "arguments_unavailable", Message: "argument rules were not evaluated",
		})
	case CaptureTruncated:
		result.Gaps = append(result.Gaps, EvaluationGap{
			Code: "arguments_truncated", Message: "only the captured argument prefix was evaluated",
		})
	}
	if observation.Operation == ExecOperationExecveat && !path.IsAbs(observation.Executable) {
		result.Gaps = append(result.Gaps, EvaluationGap{
			Code:    "execveat_resolution_unavailable",
			Message: "relative execveat path was not resolved against dirfd and flags",
		})
	}
}

func execRuleMatches(rule compiledExecRule, observation ExecObservation) (bool, MatchConfidence, []string) {
	reasons := []string{"exec_attempt_not_execution_result"}
	if observation.Operation == ExecOperationExecveat {
		reasons = append(reasons, "execveat_attempt")
	}
	switch rule.kind {
	case "exec_executable":
		if observation.Executable == "" || observation.ExecutableTruncated {
			return false, "", nil
		}
		candidate := observation.Executable
		if !strings.Contains(rule.value, "/") {
			candidate = path.Base(candidate)
		}
		matched := candidate == rule.value
		if hasGlob(rule.value) {
			matched, _ = path.Match(rule.value, candidate)
		}
		return matched, ConfidenceHeuristic, reasons
	case "exec_argument":
		if observation.ArgumentsState == CaptureUnavailable || len(observation.Arguments) == 0 {
			return false, "", nil
		}
		captured := strings.Join(observation.Arguments, " ")
		if !strings.Contains(captured, rule.value) && !slices.ContainsFunc(observation.Arguments, func(argument string) bool {
			return strings.Contains(argument, rule.value)
		}) {
			return false, "", nil
		}
		confidence := ConfidenceHeuristic
		if observation.ArgumentsState == CaptureTruncated {
			confidence = ConfidenceIncomplete
			reasons = append(reasons, "argument_capture_truncated")
		}
		return true, confidence, reasons
	default:
		return false, "", nil
	}
}
