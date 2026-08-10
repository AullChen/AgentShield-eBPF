package policy

import (
	"errors"
	"fmt"
	"slices"
	"sort"
	"sync"
	"sync/atomic"
)

// EvaluationContext contains the trusted identity used to select policy
// scopes. Empty values simply make the corresponding scope inapplicable.
type EvaluationContext struct {
	RunID    string
	CgroupID string
	Labels   map[string]string
}

type FinalDecision struct {
	PolicyID           string             `json:"policy_id"`
	RuleID             uint32             `json:"rule_id"`
	Decision           Decision           `json:"policy_decision"`
	NetworkDisposition NetworkDisposition `json:"network_disposition,omitempty"`
	RequestedAction    Action             `json:"requested_action"`
	EffectiveAction    Action             `json:"effective_action"`
	Enforced           bool               `json:"enforced"`
}

// DecisionReport retains every matching rule while identifying the single
// policy that won the deterministic scope, priority, and policy-ID ordering.
type DecisionReport struct {
	Generation Generation      `json:"generation"`
	Hits       []PolicyHit     `json:"hits"`
	Gaps       []EvaluationGap `json:"gaps,omitempty"`
	Final      *FinalDecision  `json:"final,omitempty"`
}

type NetworkDecisionReport struct {
	DecisionReport
	Decisions []NetworkPolicyDecision `json:"decisions"`
}

type engineSnapshot struct {
	generation   Generation
	bundle       Bundle
	fileRules    map[string][]compiledFileRule
	execRules    map[string][]compiledExecRule
	networkRules map[string][]compiledNetworkRule
}

type preparedEngineBundle struct {
	bundle       Bundle
	fileRules    map[string][]compiledFileRule
	execRules    map[string][]compiledExecRule
	networkRules map[string][]compiledNetworkRule
}

// Engine evaluates one immutable, precompiled bundle generation per event.
// Activate builds and validates the replacement before publishing it atomically.
type Engine struct {
	limits   Limits
	activate sync.Mutex
	active   atomic.Pointer[engineSnapshot]
}

func NewEngine(bundle Bundle, generation Generation, limits Limits) (*Engine, []Diagnostic, error) {
	if err := validateInitialGeneration(generation); err != nil {
		return nil, nil, err
	}
	prepared, diagnostics, err := prepareEngineBundle(bundle, limits)
	if err != nil {
		return nil, diagnostics, err
	}
	engine := &Engine{limits: limits.withDefaults()}
	engine.active.Store(newEngineSnapshot(generation, prepared))
	return engine, diagnostics, nil
}

// Activate accepts only a newer revision in the opposite A/B bank. A failed
// activation leaves the prior snapshot available to concurrent evaluations.
func (engine *Engine) Activate(bundle Bundle, generation Generation) ([]Diagnostic, error) {
	if engine == nil {
		return nil, errors.New("policy engine is required")
	}
	engine.activate.Lock()
	defer engine.activate.Unlock()

	current := engine.active.Load()
	if current == nil {
		return nil, errors.New("policy engine has no active generation")
	}
	if generation.Bank != BankA && generation.Bank != BankB {
		return nil, fmt.Errorf("generation bank %d is invalid", generation.Bank)
	}
	if generation.Revision <= current.generation.Revision {
		return nil, fmt.Errorf("generation revision %d must be newer than %d", generation.Revision, current.generation.Revision)
	}
	if generation.Bank == current.generation.Bank {
		return nil, fmt.Errorf("generation %d must activate the inactive bank", generation.Revision)
	}
	prepared, diagnostics, err := prepareEngineBundle(bundle, engine.limits)
	if err != nil {
		return diagnostics, err
	}
	engine.active.Store(newEngineSnapshot(generation, prepared))
	return diagnostics, nil
}

func (engine *Engine) EvaluateFile(context EvaluationContext, observation FileObservation) (DecisionReport, error) {
	if err := validateFileObservation(observation); err != nil {
		return DecisionReport{}, err
	}
	snapshot, err := engine.snapshot()
	if err != nil {
		return DecisionReport{}, err
	}
	return evaluateFileSnapshot(snapshot, context, []FileObservation{observation})
}

func evaluateFileSnapshot(snapshot *engineSnapshot, context EvaluationContext, observations []FileObservation) (DecisionReport, error) {
	bundle := selectPolicies(snapshot.bundle, context, conditionFile)
	if len(bundle.Policies) == 0 {
		return emptyDecisionReport(snapshot.generation), nil
	}
	result := MatchResult{}
	rules := selectFileRules(snapshot.fileRules, bundle)
	seenHits := make(map[uint32]struct{})
	seenGaps := make(map[string]struct{})
	for _, observation := range observations {
		if err := validateFileObservation(observation); err != nil {
			return DecisionReport{}, err
		}
		matched := matchFileRules(rules, observation)
		for _, hit := range matched.Hits {
			if _, exists := seenHits[hit.RuleID]; exists {
				continue
			}
			seenHits[hit.RuleID] = struct{}{}
			result.Hits = append(result.Hits, hit)
		}
		for _, gap := range matched.Gaps {
			key := gap.PolicyID + "\x00" + gap.Code + "\x00" + gap.Message
			if _, exists := seenGaps[key]; exists {
				continue
			}
			seenGaps[key] = struct{}{}
			result.Gaps = append(result.Gaps, gap)
		}
	}
	return buildDecisionReport(snapshot.generation, bundle, result), nil
}

func (engine *Engine) EvaluateExec(context EvaluationContext, observation ExecObservation) (DecisionReport, error) {
	if err := validateExecObservation(observation); err != nil {
		return DecisionReport{}, err
	}
	snapshot, err := engine.snapshot()
	if err != nil {
		return DecisionReport{}, err
	}
	bundle := selectPolicies(snapshot.bundle, context, conditionExec)
	if len(bundle.Policies) == 0 {
		return emptyDecisionReport(snapshot.generation), nil
	}
	result := matchExecRules(selectExecRules(snapshot.execRules, bundle), observation)
	return buildDecisionReport(snapshot.generation, bundle, result), nil
}

func (engine *Engine) EvaluateNetwork(context EvaluationContext, observation NetworkObservation) (NetworkDecisionReport, error) {
	if err := validateNetworkObservation(observation); err != nil {
		return NetworkDecisionReport{}, err
	}
	snapshot, err := engine.snapshot()
	if err != nil {
		return NetworkDecisionReport{}, err
	}
	bundle := selectPolicies(snapshot.bundle, context, conditionNetwork)
	if len(bundle.Policies) == 0 {
		return NetworkDecisionReport{DecisionReport: emptyDecisionReport(snapshot.generation)}, nil
	}
	result := matchNetworkRules(selectNetworkRules(snapshot.networkRules, bundle), observation)
	report := NetworkDecisionReport{
		DecisionReport: buildDecisionReport(snapshot.generation, bundle, result.MatchResult),
		Decisions:      result.Decisions,
	}
	if report.Final != nil {
		for _, decision := range report.Decisions {
			if decision.PolicyID == report.Final.PolicyID && decision.RuleID == report.Final.RuleID {
				report.Final.NetworkDisposition = decision.Disposition
				break
			}
		}
	}
	return report, nil
}

func (engine *Engine) snapshot() (*engineSnapshot, error) {
	if engine == nil {
		return nil, errors.New("policy engine is required")
	}
	snapshot := engine.active.Load()
	if snapshot == nil {
		return nil, errors.New("policy engine has no active generation")
	}
	return snapshot, nil
}

func prepareEngineBundle(bundle Bundle, limits Limits) (preparedEngineBundle, []Diagnostic, error) {
	prepared := cloneBundle(bundle)
	diagnostics, err := prepared.NormalizeAndValidate()
	if err != nil {
		return preparedEngineBundle{}, diagnostics, fmt.Errorf("validate policy bundle: %w", err)
	}
	if _, err := PreviewCompile(prepared, limits); err != nil {
		return preparedEngineBundle{}, diagnostics, err
	}
	fileRules, err := compileFileRules(prepared)
	if err != nil {
		return preparedEngineBundle{}, diagnostics, err
	}
	execRules, err := compileExecRules(prepared)
	if err != nil {
		return preparedEngineBundle{}, diagnostics, err
	}
	networkRules, err := compileNetworkRules(prepared)
	if err != nil {
		return preparedEngineBundle{}, diagnostics, err
	}
	return preparedEngineBundle{
		bundle:       prepared,
		fileRules:    indexFileRules(fileRules),
		execRules:    indexExecRules(execRules),
		networkRules: indexNetworkRules(networkRules),
	}, diagnostics, nil
}

func newEngineSnapshot(generation Generation, prepared preparedEngineBundle) *engineSnapshot {
	return &engineSnapshot{
		generation:   generation,
		bundle:       prepared.bundle,
		fileRules:    prepared.fileRules,
		execRules:    prepared.execRules,
		networkRules: prepared.networkRules,
	}
}

func indexFileRules(rules []compiledFileRule) map[string][]compiledFileRule {
	indexed := make(map[string][]compiledFileRule)
	for _, rule := range rules {
		indexed[rule.policy.ID] = append(indexed[rule.policy.ID], rule)
	}
	return indexed
}

func indexExecRules(rules []compiledExecRule) map[string][]compiledExecRule {
	indexed := make(map[string][]compiledExecRule)
	for _, rule := range rules {
		indexed[rule.policy.ID] = append(indexed[rule.policy.ID], rule)
	}
	return indexed
}

func indexNetworkRules(rules []compiledNetworkRule) map[string][]compiledNetworkRule {
	indexed := make(map[string][]compiledNetworkRule)
	for _, rule := range rules {
		indexed[rule.policy.ID] = append(indexed[rule.policy.ID], rule)
	}
	return indexed
}

func selectFileRules(indexed map[string][]compiledFileRule, bundle Bundle) []compiledFileRule {
	var selected []compiledFileRule
	for _, policy := range bundle.Policies {
		selected = append(selected, indexed[policy.ID]...)
	}
	return selected
}

func selectExecRules(indexed map[string][]compiledExecRule, bundle Bundle) []compiledExecRule {
	var selected []compiledExecRule
	for _, policy := range bundle.Policies {
		selected = append(selected, indexed[policy.ID]...)
	}
	return selected
}

func selectNetworkRules(indexed map[string][]compiledNetworkRule, bundle Bundle) []compiledNetworkRule {
	var selected []compiledNetworkRule
	for _, policy := range bundle.Policies {
		selected = append(selected, indexed[policy.ID]...)
	}
	return selected
}

type conditionKind uint8

const (
	conditionFile conditionKind = iota
	conditionExec
	conditionNetwork
)

func selectPolicies(bundle Bundle, context EvaluationContext, kind conditionKind) Bundle {
	selected := Bundle{SchemaVersion: bundle.SchemaVersion}
	for _, policy := range bundle.Policies {
		if !policy.Enabled || !scopeMatches(policy.Scope, context) || !hasCondition(policy, kind) {
			continue
		}
		selected.Policies = append(selected.Policies, policy)
	}
	sort.SliceStable(selected.Policies, func(i, j int) bool {
		return HigherPrecedence(selected.Policies[i], selected.Policies[j])
	})
	return selected
}

func hasCondition(policy Policy, kind conditionKind) bool {
	switch kind {
	case conditionFile:
		return policy.Conditions.File != nil
	case conditionExec:
		return policy.Conditions.Exec != nil
	case conditionNetwork:
		return policy.Conditions.Network != nil
	default:
		return false
	}
}

func scopeMatches(scope Scope, context EvaluationContext) bool {
	switch scope.Type {
	case ScopeGlobal:
		return true
	case ScopeRun:
		return context.RunID != "" && context.RunID == scope.RunID
	case ScopeCgroup:
		return context.CgroupID != "" && context.CgroupID == scope.CgroupID
	case ScopeLabels:
		for key, value := range scope.LabelSelector {
			if context.Labels[key] != value {
				return false
			}
		}
		return true
	default:
		return false
	}
}

func buildDecisionReport(generation Generation, bundle Bundle, result MatchResult) DecisionReport {
	report := DecisionReport{
		Generation: generation,
		Hits:       slices.Clone(result.Hits),
		Gaps:       slices.Clone(result.Gaps),
	}
	rank := make(map[string]int, len(bundle.Policies))
	for index, policy := range bundle.Policies {
		rank[policy.ID] = index
	}
	sort.SliceStable(report.Hits, func(i, j int) bool {
		return rank[report.Hits[i].PolicyID] < rank[report.Hits[j].PolicyID]
	})
	if len(report.Hits) == 0 {
		return report
	}
	policies := make(map[string]Policy, len(bundle.Policies))
	for _, policy := range bundle.Policies {
		policies[policy.ID] = policy
	}
	winner := report.Hits[0]
	policy := policies[winner.PolicyID]
	report.Final = &FinalDecision{
		PolicyID:        winner.PolicyID,
		RuleID:          winner.RuleID,
		Decision:        policy.Decision,
		RequestedAction: winner.RequestedAction,
		EffectiveAction: winner.EffectiveAction,
		Enforced:        winner.Enforced,
	}
	return report
}

func emptyDecisionReport(generation Generation) DecisionReport {
	return DecisionReport{Generation: generation, Hits: []PolicyHit{}}
}

func validateInitialGeneration(generation Generation) error {
	if generation.Revision == 0 {
		return errors.New("generation revision must be non-zero")
	}
	if generation.Bank != BankA && generation.Bank != BankB {
		return fmt.Errorf("generation bank %d is invalid", generation.Bank)
	}
	return nil
}

func cloneBundle(bundle Bundle) Bundle {
	cloned := Bundle{SchemaVersion: bundle.SchemaVersion, Policies: make([]Policy, len(bundle.Policies))}
	for index, policy := range bundle.Policies {
		cloned.Policies[index] = policy
		cloned.Policies[index].Scope.LabelSelector = cloneStringMap(policy.Scope.LabelSelector)
		if condition := policy.Conditions.File; condition != nil {
			copy := *condition
			copy.ExactPaths = slices.Clone(condition.ExactPaths)
			copy.Prefixes = slices.Clone(condition.Prefixes)
			copy.Suffixes = slices.Clone(condition.Suffixes)
			copy.Basenames = slices.Clone(condition.Basenames)
			copy.Access = slices.Clone(condition.Access)
			cloned.Policies[index].Conditions.File = &copy
		}
		if condition := policy.Conditions.Exec; condition != nil {
			copy := *condition
			copy.Executables = slices.Clone(condition.Executables)
			copy.ArgContains = slices.Clone(condition.ArgContains)
			cloned.Policies[index].Conditions.Exec = &copy
		}
		if condition := policy.Conditions.Network; condition != nil {
			copy := *condition
			copy.CIDRs = slices.Clone(condition.CIDRs)
			copy.Ports = slices.Clone(condition.Ports)
			copy.Families = slices.Clone(condition.Families)
			cloned.Policies[index].Conditions.Network = &copy
		}
	}
	return cloned
}

func cloneStringMap(values map[string]string) map[string]string {
	if values == nil {
		return nil
	}
	cloned := make(map[string]string, len(values))
	for key, value := range values {
		cloned[key] = value
	}
	return cloned
}
