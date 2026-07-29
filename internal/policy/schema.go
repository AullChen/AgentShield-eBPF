package policy

import (
	"errors"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
)

const SchemaVersion = 1

type Decision string

const (
	DecisionObserve Decision = "observe"
	DecisionAllow   Decision = "allow"
	DecisionDeny    Decision = "deny"
)

type Action string

const (
	ActionAudit   Action = "audit"
	ActionAlert   Action = "alert"
	ActionBlock   Action = "block"
	ActionContain Action = "contain"
	ActionKill    Action = "kill"
)

type Severity string

const (
	SeverityInfo     Severity = "info"
	SeverityLow      Severity = "low"
	SeverityMedium   Severity = "medium"
	SeverityHigh     Severity = "high"
	SeverityCritical Severity = "critical"
)

type ScopeType string

const (
	ScopeGlobal ScopeType = "global"
	ScopeLabels ScopeType = "labels"
	ScopeCgroup ScopeType = "cgroup"
	ScopeRun    ScopeType = "run"
)

type Bundle struct {
	SchemaVersion int      `json:"schema_version" yaml:"schema_version"`
	Policies      []Policy `json:"policies" yaml:"policies"`
}

type Policy struct {
	ID              string     `json:"id" yaml:"id"`
	Name            string     `json:"name" yaml:"name"`
	Description     string     `json:"description,omitempty" yaml:"description,omitempty"`
	Enabled         bool       `json:"enabled" yaml:"enabled"`
	Scope           Scope      `json:"scope" yaml:"scope"`
	Decision        Decision   `json:"policy_decision" yaml:"policy_decision"`
	RequestedAction Action     `json:"requested_action" yaml:"requested_action"`
	Priority        int        `json:"priority" yaml:"priority"`
	Severity        Severity   `json:"severity" yaml:"severity"`
	Conditions      Conditions `json:"conditions" yaml:"conditions"`
}

type Scope struct {
	Type          ScopeType         `json:"type" yaml:"type"`
	RunID         string            `json:"run_id,omitempty" yaml:"run_id,omitempty"`
	CgroupID      string            `json:"cgroup_id,omitempty" yaml:"cgroup_id,omitempty"`
	LabelSelector map[string]string `json:"label_selector,omitempty" yaml:"label_selector,omitempty"`
}

type Conditions struct {
	File    *FileCondition    `json:"file,omitempty" yaml:"file,omitempty"`
	Exec    *ExecCondition    `json:"exec,omitempty" yaml:"exec,omitempty"`
	Network *NetworkCondition `json:"network,omitempty" yaml:"network,omitempty"`
}

type FileCondition struct {
	ExactPaths []string     `json:"exact_paths,omitempty" yaml:"exact_paths,omitempty"`
	Prefixes   []string     `json:"prefixes,omitempty" yaml:"prefixes,omitempty"`
	Suffixes   []string     `json:"suffixes,omitempty" yaml:"suffixes,omitempty"`
	Basenames  []string     `json:"basenames,omitempty" yaml:"basenames,omitempty"`
	Access     []FileAccess `json:"access" yaml:"access"`
}

type FileAccess string

const (
	FileRead    FileAccess = "read"
	FileWrite   FileAccess = "write"
	FileExecute FileAccess = "execute"
)

type ExecCondition struct {
	Executables []string `json:"executables,omitempty" yaml:"executables,omitempty"`
	ArgContains []string `json:"arg_contains,omitempty" yaml:"arg_contains,omitempty"`
}

type NetworkCondition struct {
	Default  NetworkDefault `json:"default" yaml:"default"`
	CIDRs    []string       `json:"cidrs,omitempty" yaml:"cidrs,omitempty"`
	Ports    []PortRange    `json:"ports,omitempty" yaml:"ports,omitempty"`
	Families []IPFamily     `json:"families" yaml:"families"`
}

type NetworkDefault string

const (
	NetworkDefaultObserve NetworkDefault = "default_observe"
	NetworkDefaultDeny    NetworkDefault = "default_deny"
)

type IPFamily string

const (
	FamilyIPv4 IPFamily = "ipv4"
	FamilyIPv6 IPFamily = "ipv6"
)

type PortRange struct {
	From uint16 `json:"from" yaml:"from"`
	To   uint16 `json:"to" yaml:"to"`
}

type Diagnostic struct {
	Code     string
	PolicyID string
	Message  string
}

func (bundle *Bundle) NormalizeAndValidate() ([]Diagnostic, error) {
	if bundle == nil {
		return nil, errors.New("policy bundle is required")
	}
	var diagnostics []Diagnostic
	for index := range bundle.Policies {
		policy := &bundle.Policies[index]
		if policy.RequestedAction == ActionKill {
			policy.RequestedAction = ActionContain
			diagnostics = append(diagnostics, Diagnostic{
				Code:     "deprecated_action_kill",
				PolicyID: policy.ID,
				Message:  `requested_action "kill" is deprecated; normalized to "contain"`,
			})
		}
	}
	return diagnostics, bundle.Validate()
}

func (bundle Bundle) Validate() error {
	var validationErrors []error
	if bundle.SchemaVersion != SchemaVersion {
		validationErrors = append(validationErrors,
			fmt.Errorf("schema_version: got %d, want %d", bundle.SchemaVersion, SchemaVersion))
	}
	if len(bundle.Policies) == 0 {
		validationErrors = append(validationErrors, errors.New("policies: at least one policy is required"))
	}
	seenIDs := make(map[string]struct{}, len(bundle.Policies))
	for index, policy := range bundle.Policies {
		if _, exists := seenIDs[policy.ID]; exists && policy.ID != "" {
			validationErrors = append(validationErrors,
				fmt.Errorf("policies[%d].id: duplicate policy ID %q", index, policy.ID))
		}
		seenIDs[policy.ID] = struct{}{}
		if err := policy.Validate(); err != nil {
			validationErrors = append(validationErrors, fmt.Errorf("policies[%d]: %w", index, err))
		}
	}
	return errors.Join(validationErrors...)
}

func (policy Policy) Validate() error {
	var validationErrors []error
	if strings.TrimSpace(policy.ID) == "" {
		validationErrors = append(validationErrors, errors.New("id is required"))
	}
	if strings.TrimSpace(policy.Name) == "" {
		validationErrors = append(validationErrors, errors.New("name is required"))
	}
	if err := policy.Scope.Validate(); err != nil {
		validationErrors = append(validationErrors, fmt.Errorf("scope: %w", err))
	}
	if !validDecisionAction(policy.Decision, policy.RequestedAction) {
		validationErrors = append(validationErrors, fmt.Errorf(
			"requested_action %q is not valid for policy_decision %q",
			policy.RequestedAction,
			policy.Decision,
		))
	}
	if !validSeverity(policy.Severity) {
		validationErrors = append(validationErrors, fmt.Errorf("severity %q is not supported", policy.Severity))
	}
	if err := policy.Conditions.Validate(); err != nil {
		validationErrors = append(validationErrors, fmt.Errorf("conditions: %w", err))
	}
	return errors.Join(validationErrors...)
}

func (scope Scope) Validate() error {
	switch scope.Type {
	case ScopeGlobal:
		if scope.RunID != "" || scope.CgroupID != "" || len(scope.LabelSelector) != 0 {
			return errors.New("global scope must not include run_id, cgroup_id, or label_selector")
		}
	case ScopeRun:
		if strings.TrimSpace(scope.RunID) == "" || scope.CgroupID != "" || len(scope.LabelSelector) != 0 {
			return errors.New("run scope requires only run_id")
		}
	case ScopeCgroup:
		if scope.RunID != "" || len(scope.LabelSelector) != 0 {
			return errors.New("cgroup scope requires only cgroup_id")
		}
		cgroupID, err := strconv.ParseUint(scope.CgroupID, 10, 64)
		if err != nil || cgroupID == 0 {
			return errors.New("cgroup scope requires a non-zero decimal cgroup_id")
		}
	case ScopeLabels:
		if scope.RunID != "" || scope.CgroupID != "" || len(scope.LabelSelector) == 0 {
			return errors.New("labels scope requires only a non-empty label_selector")
		}
		for key, value := range scope.LabelSelector {
			if strings.TrimSpace(key) == "" || strings.TrimSpace(value) == "" {
				return errors.New("label_selector keys and values must be non-empty")
			}
		}
	default:
		return fmt.Errorf("type %q is not supported", scope.Type)
	}
	return nil
}

func (conditions Conditions) Validate() error {
	count := 0
	if conditions.File != nil {
		count++
	}
	if conditions.Exec != nil {
		count++
	}
	if conditions.Network != nil {
		count++
	}
	if count != 1 {
		return errors.New("select exactly one of file, exec, or network")
	}
	if conditions.File != nil {
		return conditions.File.Validate()
	}
	if conditions.Exec != nil {
		return conditions.Exec.Validate()
	}
	return conditions.Network.Validate()
}

func (condition FileCondition) Validate() error {
	if len(condition.ExactPaths)+len(condition.Prefixes)+len(condition.Suffixes)+len(condition.Basenames) == 0 {
		return errors.New("file condition requires at least one path, prefix, suffix, or basename")
	}
	if len(condition.Access) == 0 {
		return errors.New("file condition requires at least one access mode")
	}
	for _, access := range condition.Access {
		if access != FileRead && access != FileWrite && access != FileExecute {
			return fmt.Errorf("file access %q is not supported", access)
		}
	}
	if duplicate, exists := firstDuplicate(condition.Access); exists {
		return fmt.Errorf("file access %q is duplicated", duplicate)
	}
	return validateNonEmptyStrings(
		condition.ExactPaths,
		condition.Prefixes,
		condition.Suffixes,
		condition.Basenames,
	)
}

func (condition ExecCondition) Validate() error {
	if len(condition.Executables)+len(condition.ArgContains) == 0 {
		return errors.New("exec condition requires an executable or argument fragment")
	}
	return validateNonEmptyStrings(condition.Executables, condition.ArgContains)
}

func (condition NetworkCondition) Validate() error {
	if condition.Default != NetworkDefaultObserve && condition.Default != NetworkDefaultDeny {
		return fmt.Errorf("network default %q is not supported", condition.Default)
	}
	if len(condition.Families) == 0 {
		return errors.New("network condition requires at least one IP family")
	}
	for _, family := range condition.Families {
		if family != FamilyIPv4 && family != FamilyIPv6 {
			return fmt.Errorf("IP family %q is not supported", family)
		}
	}
	if duplicate, exists := firstDuplicate(condition.Families); exists {
		return fmt.Errorf("IP family %q is duplicated", duplicate)
	}
	for _, cidr := range condition.CIDRs {
		if _, err := netip.ParsePrefix(cidr); err != nil {
			return fmt.Errorf("CIDR %q is invalid: %w", cidr, err)
		}
	}
	for _, portRange := range condition.Ports {
		if portRange.From == 0 || portRange.To < portRange.From {
			return fmt.Errorf("port range %d-%d is invalid", portRange.From, portRange.To)
		}
	}
	return nil
}

func HigherPrecedence(first, second Policy) bool {
	firstSpecificity := first.Scope.specificity()
	secondSpecificity := second.Scope.specificity()
	if firstSpecificity != secondSpecificity {
		return firstSpecificity > secondSpecificity
	}
	if first.Priority != second.Priority {
		return first.Priority > second.Priority
	}
	return first.ID < second.ID
}

func (scope Scope) specificity() int {
	switch scope.Type {
	case ScopeRun:
		return 3
	case ScopeCgroup:
		return 2
	case ScopeLabels:
		return 1
	case ScopeGlobal:
		return 0
	default:
		return -1
	}
}

func validDecisionAction(decision Decision, action Action) bool {
	switch decision {
	case DecisionObserve:
		return action == ActionAudit || action == ActionAlert
	case DecisionAllow:
		return action == ActionAudit
	case DecisionDeny:
		return action == ActionAudit || action == ActionAlert ||
			action == ActionBlock || action == ActionContain
	default:
		return false
	}
}

func validSeverity(severity Severity) bool {
	switch severity {
	case SeverityInfo, SeverityLow, SeverityMedium, SeverityHigh, SeverityCritical:
		return true
	default:
		return false
	}
}

func validateNonEmptyStrings(groups ...[]string) error {
	for _, group := range groups {
		for _, value := range group {
			if strings.TrimSpace(value) == "" {
				return errors.New("condition values must be non-empty")
			}
		}
	}
	return nil
}

func firstDuplicate[T comparable](values []T) (T, bool) {
	seen := make(map[T]struct{}, len(values))
	for _, value := range values {
		if _, exists := seen[value]; exists {
			return value, true
		}
		seen[value] = struct{}{}
	}
	var zero T
	return zero, false
}
