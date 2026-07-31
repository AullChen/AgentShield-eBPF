package policy

import (
	"fmt"
	"path"
	"strings"
)

const (
	defaultMaxFileBytes          int64 = 1 << 20
	defaultMaxPolicies                 = 256
	defaultMaxStringBytes              = 256
	defaultMaxConditionValues          = 64
	defaultMaxGlobMetacharacters       = 4
	defaultKernelMapCapacity           = 1024
	defaultMaxUserSpaceRules           = 1024
)

// Limits bounds policy input and the number of entries emitted by a preview.
// Zero-valued fields use the corresponding defaults returned by DefaultLimits.
type Limits struct {
	MaxFileBytes          int64
	MaxPolicies           int
	MaxStringBytes        int
	MaxConditionValues    int
	MaxGlobMetacharacters int
	KernelMapCapacity     int
	MaxUserSpaceRules     int
}

func DefaultLimits() Limits {
	return Limits{
		MaxFileBytes:          defaultMaxFileBytes,
		MaxPolicies:           defaultMaxPolicies,
		MaxStringBytes:        defaultMaxStringBytes,
		MaxConditionValues:    defaultMaxConditionValues,
		MaxGlobMetacharacters: defaultMaxGlobMetacharacters,
		KernelMapCapacity:     defaultKernelMapCapacity,
		MaxUserSpaceRules:     defaultMaxUserSpaceRules,
	}
}

func (limits Limits) withDefaults() Limits {
	defaults := DefaultLimits()
	if limits.MaxFileBytes <= 0 {
		limits.MaxFileBytes = defaults.MaxFileBytes
	}
	if limits.MaxPolicies <= 0 {
		limits.MaxPolicies = defaults.MaxPolicies
	}
	if limits.MaxStringBytes <= 0 {
		limits.MaxStringBytes = defaults.MaxStringBytes
	}
	if limits.MaxConditionValues <= 0 {
		limits.MaxConditionValues = defaults.MaxConditionValues
	}
	if limits.MaxGlobMetacharacters <= 0 {
		limits.MaxGlobMetacharacters = defaults.MaxGlobMetacharacters
	}
	if limits.KernelMapCapacity <= 0 {
		limits.KernelMapCapacity = defaults.KernelMapCapacity
	}
	if limits.MaxUserSpaceRules <= 0 {
		limits.MaxUserSpaceRules = defaults.MaxUserSpaceRules
	}
	return limits
}

func validateBundleLimits(bundle Bundle, limits Limits) error {
	if len(bundle.Policies) > limits.MaxPolicies {
		return fmt.Errorf("policies: got %d, limit is %d", len(bundle.Policies), limits.MaxPolicies)
	}
	for index, policy := range bundle.Policies {
		if err := validatePolicyLimits(policy, limits); err != nil {
			return fmt.Errorf("policies[%d]: %w", index, err)
		}
	}
	return nil
}

func validatePolicyLimits(policy Policy, limits Limits) error {
	stringsToCheck := []struct {
		field string
		value string
	}{
		{"id", policy.ID},
		{"name", policy.Name},
		{"description", policy.Description},
		{"scope.run_id", policy.Scope.RunID},
		{"scope.cgroup_id", policy.Scope.CgroupID},
	}
	for key, value := range policy.Scope.LabelSelector {
		stringsToCheck = append(stringsToCheck,
			struct{ field, value string }{"scope.label_selector key", key},
			struct{ field, value string }{"scope.label_selector value", value},
		)
	}
	if len(policy.Scope.LabelSelector) > limits.MaxConditionValues {
		return fmt.Errorf("scope.label_selector: got %d entries, limit is %d", len(policy.Scope.LabelSelector), limits.MaxConditionValues)
	}

	conditionValues := 0
	var conditionStrings []string
	var globPatterns []string
	if condition := policy.Conditions.File; condition != nil {
		conditionStrings = append(conditionStrings, condition.ExactPaths...)
		conditionStrings = append(conditionStrings, condition.Prefixes...)
		conditionStrings = append(conditionStrings, condition.Suffixes...)
		conditionStrings = append(conditionStrings, condition.Basenames...)
		globPatterns = append(globPatterns, condition.ExactPaths...)
		conditionValues = len(conditionStrings) + len(condition.Access)
	}
	if condition := policy.Conditions.Exec; condition != nil {
		conditionStrings = append(conditionStrings, condition.Executables...)
		conditionStrings = append(conditionStrings, condition.ArgContains...)
		globPatterns = append(globPatterns, condition.Executables...)
		conditionValues = len(conditionStrings)
	}
	if condition := policy.Conditions.Network; condition != nil {
		conditionStrings = append(conditionStrings, condition.CIDRs...)
		conditionValues = len(condition.CIDRs) + len(condition.Ports) + len(condition.Families)
	}
	if conditionValues > limits.MaxConditionValues {
		return fmt.Errorf("conditions: got %d values, limit is %d", conditionValues, limits.MaxConditionValues)
	}
	for _, value := range conditionStrings {
		stringsToCheck = append(stringsToCheck, struct{ field, value string }{"condition value", value})
	}
	for _, value := range globPatterns {
		if !hasGlob(value) {
			continue
		}
		if _, err := path.Match(value, "policy-preview-probe"); err != nil {
			return fmt.Errorf("condition glob %q is invalid: %w", value, err)
		}
		if count := globMetacharacters(value); count > limits.MaxGlobMetacharacters {
			return fmt.Errorf("condition glob %q has %d metacharacters, limit is %d", value, count, limits.MaxGlobMetacharacters)
		}
	}
	for _, item := range stringsToCheck {
		if len(item.value) > limits.MaxStringBytes {
			return fmt.Errorf("%s: got %d bytes, limit is %d", item.field, len(item.value), limits.MaxStringBytes)
		}
	}
	return nil
}

func hasGlob(value string) bool {
	return strings.ContainsAny(value, "*?[")
}

func globMetacharacters(value string) int {
	return strings.Count(value, "*") + strings.Count(value, "?") + strings.Count(value, "[")
}
