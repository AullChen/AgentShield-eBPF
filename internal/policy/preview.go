package policy

import (
	"errors"
	"fmt"
	"path"
	"slices"
)

type ExecutionClass string

const (
	ExecutionDisabled      ExecutionClass = "disabled"
	ExecutionKernel        ExecutionClass = "kernel_eligible"
	ExecutionUserSpaceOnly ExecutionClass = "user_space_only"
	ExecutionMixed         ExecutionClass = "mixed"
)

type CompilePreview struct {
	Policies              []PolicyPreview `json:"policies"`
	KernelRuleCount       int             `json:"kernel_rule_count"`
	UserSpaceRuleCount    int             `json:"user_space_rule_count"`
	KernelMapCapacity     int             `json:"kernel_map_capacity"`
	UserSpaceRuleCapacity int             `json:"user_space_rule_capacity"`
}

type PolicyPreview struct {
	PolicyID           string         `json:"policy_id"`
	Execution          ExecutionClass `json:"execution"`
	RequestedAction    Action         `json:"requested_action"`
	KernelRuleCount    int            `json:"kernel_rule_count"`
	UserSpaceRuleCount int            `json:"user_space_rule_count"`
	FallbackRequired   bool           `json:"fallback_required"`
	Reasons            []string       `json:"reasons,omitempty"`
}

// PreviewCompile validates resource bounds and estimates how a policy bundle
// would be split between kernel maps and post-event user-space evaluation.
// It does not claim that the required eBPF hooks have already been attached.
func PreviewCompile(bundle Bundle, limits Limits) (CompilePreview, error) {
	limits = limits.withDefaults()
	preview := CompilePreview{
		Policies:              make([]PolicyPreview, 0, len(bundle.Policies)),
		KernelMapCapacity:     limits.KernelMapCapacity,
		UserSpaceRuleCapacity: limits.MaxUserSpaceRules,
	}
	if err := validateBundleLimits(bundle, limits); err != nil {
		return preview, fmt.Errorf("validate policy limits: %w", err)
	}
	if err := bundle.Validate(); err != nil {
		return preview, fmt.Errorf("validate policy bundle: %w", err)
	}

	var compileErrors []error
	for _, policy := range bundle.Policies {
		policyPreview := previewPolicy(policy)
		preview.Policies = append(preview.Policies, policyPreview)
		preview.KernelRuleCount += policyPreview.KernelRuleCount
		preview.UserSpaceRuleCount += policyPreview.UserSpaceRuleCount
		if policy.RequestedAction == ActionBlock && policyPreview.UserSpaceRuleCount > 0 {
			compileErrors = append(compileErrors, fmt.Errorf(
				"policy %q requests block but requires user-space evaluation (%v)",
				policy.ID,
				policyPreview.Reasons,
			))
		}
	}
	if preview.KernelRuleCount > limits.KernelMapCapacity {
		compileErrors = append(compileErrors, fmt.Errorf(
			"kernel rule estimate %d exceeds map capacity %d",
			preview.KernelRuleCount,
			limits.KernelMapCapacity,
		))
	}
	if preview.UserSpaceRuleCount > limits.MaxUserSpaceRules {
		compileErrors = append(compileErrors, fmt.Errorf(
			"user-space rule estimate %d exceeds capacity %d",
			preview.UserSpaceRuleCount,
			limits.MaxUserSpaceRules,
		))
	}
	return preview, errors.Join(compileErrors...)
}

func previewPolicy(policy Policy) PolicyPreview {
	preview := PolicyPreview{
		PolicyID:        policy.ID,
		RequestedAction: policy.RequestedAction,
	}
	if !policy.Enabled {
		preview.Execution = ExecutionDisabled
		preview.Reasons = []string{"policy_disabled"}
		return preview
	}

	switch {
	case policy.Conditions.File != nil:
		previewFile(policy.Conditions.File, &preview)
	case policy.Conditions.Exec != nil:
		previewExec(policy.Conditions.Exec, &preview)
	case policy.Conditions.Network != nil:
		previewNetwork(policy.Conditions.Network, &preview)
	}
	preview.FallbackRequired = preview.UserSpaceRuleCount > 0
	switch {
	case preview.KernelRuleCount > 0 && preview.UserSpaceRuleCount > 0:
		preview.Execution = ExecutionMixed
	case preview.UserSpaceRuleCount > 0:
		preview.Execution = ExecutionUserSpaceOnly
	default:
		preview.Execution = ExecutionKernel
	}
	slices.Sort(preview.Reasons)
	preview.Reasons = slices.Compact(preview.Reasons)
	return preview
}

func previewFile(condition *FileCondition, preview *PolicyPreview) {
	for _, exactPath := range condition.ExactPaths {
		switch {
		case hasGlob(exactPath):
			preview.UserSpaceRuleCount++
			preview.Reasons = append(preview.Reasons, "file_glob_requires_user_space")
		case !path.IsAbs(exactPath):
			preview.UserSpaceRuleCount++
			preview.Reasons = append(preview.Reasons, "relative_file_path_requires_user_space")
		default:
			preview.KernelRuleCount++
		}
	}
	preview.UserSpaceRuleCount += len(condition.Prefixes)
	if len(condition.Prefixes) > 0 {
		preview.Reasons = append(preview.Reasons, "file_prefix_requires_user_space")
	}
	preview.UserSpaceRuleCount += len(condition.Suffixes)
	if len(condition.Suffixes) > 0 {
		preview.Reasons = append(preview.Reasons, "file_suffix_requires_user_space")
	}
	preview.UserSpaceRuleCount += len(condition.Basenames)
	if len(condition.Basenames) > 0 {
		preview.Reasons = append(preview.Reasons, "file_basename_requires_user_space")
	}
}

func previewExec(condition *ExecCondition, preview *PolicyPreview) {
	for _, executable := range condition.Executables {
		if hasGlob(executable) {
			preview.UserSpaceRuleCount++
			preview.Reasons = append(preview.Reasons, "executable_glob_requires_user_space")
			continue
		}
		preview.KernelRuleCount++
	}
	preview.UserSpaceRuleCount += len(condition.ArgContains)
	if len(condition.ArgContains) > 0 {
		preview.Reasons = append(preview.Reasons, "exec_argument_requires_user_space")
	}
}

func previewNetwork(condition *NetworkCondition, preview *PolicyPreview) {
	preview.KernelRuleCount = len(condition.CIDRs) + len(condition.Ports)
	if preview.KernelRuleCount == 0 {
		preview.KernelRuleCount = len(condition.Families)
	}
}
