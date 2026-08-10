package policy

import (
	"errors"
	"fmt"
	"net/netip"
	"slices"
)

type NetworkProtocol string

const (
	ProtocolTCP NetworkProtocol = "tcp"
	ProtocolUDP NetworkProtocol = "udp"
)

type NetworkDisposition string

const (
	DispositionObserved      NetworkDisposition = "observed"
	DispositionAllowed       NetworkDisposition = "allowed"
	DispositionDenied        NetworkDisposition = "denied"
	DispositionNotApplicable NetworkDisposition = "not_applicable"
)

type NetworkObservation struct {
	Destination      netip.Addr
	Port             uint16
	Protocol         NetworkProtocol
	ObservedHostname string
}

type NetworkPolicyDecision struct {
	PolicyID    string             `json:"policy_id"`
	RuleID      uint32             `json:"rule_id"`
	Disposition NetworkDisposition `json:"disposition"`
	MatchedCIDR string             `json:"matched_cidr,omitempty"`
	MatchedPort *PortRange         `json:"matched_port,omitempty"`
	Enforced    bool               `json:"enforced"`
	Reasons     []string           `json:"reasons,omitempty"`
}

type NetworkMatchResult struct {
	MatchResult
	Decisions []NetworkPolicyDecision `json:"decisions"`
}

type compiledNetworkRule struct {
	policy Policy
	id     uint32
}

func MatchNetwork(bundle Bundle, observation NetworkObservation) (NetworkMatchResult, error) {
	if err := bundle.Validate(); err != nil {
		return NetworkMatchResult{}, fmt.Errorf("validate policy bundle: %w", err)
	}
	if err := validateNetworkObservation(observation); err != nil {
		return NetworkMatchResult{}, err
	}
	rules, err := compileNetworkRules(bundle)
	if err != nil {
		return NetworkMatchResult{}, err
	}
	return matchNetworkRules(rules, observation), nil
}

func compileNetworkRules(bundle Bundle) ([]compiledNetworkRule, error) {
	registry := make(ruleIDRegistry)
	var rules []compiledNetworkRule
	for _, policy := range bundle.Policies {
		condition := policy.Conditions.Network
		if !policy.Enabled || condition == nil {
			continue
		}
		if err := validateNetworkPolicyMode(policy); err != nil {
			return nil, err
		}
		ruleID, err := registry.add(policy.ID, "network_default", 0)
		if err != nil {
			return nil, err
		}
		rules = append(rules, compiledNetworkRule{policy: policy, id: ruleID})
	}
	return rules, nil
}

func matchNetworkRules(rules []compiledNetworkRule, observation NetworkObservation) NetworkMatchResult {
	observation.Destination = observation.Destination.Unmap()
	result := NetworkMatchResult{}
	for _, rule := range rules {
		policy := rule.policy
		decision := evaluateNetworkPolicy(policy, rule.id, observation)
		result.Decisions = append(result.Decisions, decision)
		if observation.ObservedHostname != "" {
			result.Gaps = append(result.Gaps, EvaluationGap{
				PolicyID: policy.ID,
				Code:     "dynamic_hostname_observe_only",
				Message:  "observed hostname did not participate in the allow decision",
			})
		}
		if decision.Disposition != DispositionObserved &&
			decision.Disposition != DispositionAllowed &&
			decision.Disposition != DispositionDenied {
			continue
		}
		effectiveAction := policy.RequestedAction
		containmentHint := false
		if decision.Disposition == DispositionAllowed {
			effectiveAction = ActionAudit
		} else if decision.Disposition == DispositionDenied &&
			(effectiveAction == ActionBlock || effectiveAction == ActionContain) {
			effectiveAction = ActionAudit
			containmentHint = policy.RequestedAction == ActionContain
		}
		result.Hits = append(result.Hits, PolicyHit{
			PolicyID:        policy.ID,
			RuleID:          rule.id,
			RuleKind:        networkRuleKind(decision.Disposition),
			RequestedAction: policy.RequestedAction,
			EffectiveAction: effectiveAction,
			EvidenceSource:  EvidenceNetworkTuple,
			Confidence:      ConfidenceExact,
			PostEventOnly:   true,
			ContainmentHint: containmentHint,
			Enforced:        false,
			Reasons:         decision.Reasons,
		})
	}
	return result
}

func validateNetworkObservation(observation NetworkObservation) error {
	if !observation.Destination.IsValid() {
		return errors.New("network observation requires a valid destination address")
	}
	if observation.Port == 0 {
		return errors.New("network observation requires a non-zero destination port")
	}
	if observation.Protocol != ProtocolTCP && observation.Protocol != ProtocolUDP {
		return fmt.Errorf("network protocol %q is not supported", observation.Protocol)
	}
	return nil
}

func validateNetworkPolicyMode(policy Policy) error {
	condition := policy.Conditions.Network
	if condition.Default == NetworkDefaultObserve {
		if policy.RequestedAction != ActionAudit && policy.RequestedAction != ActionAlert {
			return fmt.Errorf("network observe policy %q supports only audit or alert", policy.ID)
		}
		return nil
	}
	if policy.Decision != DecisionDeny {
		return fmt.Errorf("network default_deny policy %q requires policy_decision deny", policy.ID)
	}
	return nil
}

func evaluateNetworkPolicy(policy Policy, ruleID uint32, observation NetworkObservation) NetworkPolicyDecision {
	condition := policy.Conditions.Network
	family := FamilyIPv6
	if observation.Destination.Is4() {
		family = FamilyIPv4
	}
	familyMatch := slices.Contains(condition.Families, family)
	cidrMatch, matchedCIDR := matchCIDR(condition.CIDRs, observation.Destination)
	portMatch, matchedPort := matchPort(condition.Ports, observation.Port)
	selected := familyMatch && cidrMatch && portMatch
	if condition.Default == NetworkDefaultDeny {
		selected = selected && observation.Protocol == ProtocolTCP &&
			(len(condition.CIDRs) > 0 || len(condition.Ports) > 0)
	}
	decision := NetworkPolicyDecision{
		PolicyID: policy.ID, RuleID: ruleID, Disposition: DispositionNotApplicable,
		MatchedCIDR: matchedCIDR, MatchedPort: matchedPort, Enforced: false,
	}
	if condition.Default == NetworkDefaultObserve {
		if selected {
			decision.Disposition = DispositionObserved
			decision.Reasons = []string{"network_tuple_observed"}
		}
		return decision
	}
	if selected {
		decision.Disposition = DispositionAllowed
		decision.Reasons = []string{"static_network_allowlist_match"}
		return decision
	}
	decision.Disposition = DispositionDenied
	decision.Reasons = append(networkDenyReasons(observation), "enforcement_not_connected")
	return decision
}

func matchCIDR(cidrs []string, address netip.Addr) (bool, string) {
	if len(cidrs) == 0 {
		return true, ""
	}
	for _, raw := range cidrs {
		prefix, _ := netip.ParsePrefix(raw)
		if prefix.Contains(address) {
			return true, raw
		}
	}
	return false, ""
}

func matchPort(ranges []PortRange, port uint16) (bool, *PortRange) {
	if len(ranges) == 0 {
		return true, nil
	}
	for _, portRange := range ranges {
		if port >= portRange.From && port <= portRange.To {
			matched := portRange
			return true, &matched
		}
	}
	return false, nil
}

func networkDenyReasons(observation NetworkObservation) []string {
	switch {
	case observation.Port == 53:
		return []string{"direct_dns_not_allowed"}
	case observation.Protocol == ProtocolUDP && observation.Port == 443:
		return []string{"direct_quic_not_allowed"}
	case observation.Protocol == ProtocolTCP && observation.Port == 443:
		return []string{"direct_https_or_doh_not_allowed"}
	default:
		return []string{"proxy_bypass_not_allowed"}
	}
}

func networkRuleKind(disposition NetworkDisposition) string {
	switch disposition {
	case DispositionAllowed:
		return "network_allow"
	case DispositionDenied:
		return "network_default_deny"
	default:
		return "network_observe"
	}
}
