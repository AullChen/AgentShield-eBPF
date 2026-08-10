package policy

import (
	"net/netip"
	"path/filepath"
	"strings"
	"testing"
)

func TestMatchNetworkObservesStaticTuple(t *testing.T) {
	policy := networkObservePolicy()
	result, err := MatchNetwork(
		Bundle{SchemaVersion: SchemaVersion, Policies: []Policy{policy}},
		NetworkObservation{Destination: netip.MustParseAddr("2001:db8::1"), Port: 443, Protocol: ProtocolTCP},
	)
	if err != nil {
		t.Fatalf("MatchNetwork: %v", err)
	}
	if len(result.Decisions) != 1 || result.Decisions[0].Disposition != DispositionObserved {
		t.Fatalf("decisions = %+v", result.Decisions)
	}
	if len(result.Hits) != 1 || result.Hits[0].RuleKind != "network_observe" || result.Hits[0].Enforced {
		t.Fatalf("hits = %+v", result.Hits)
	}
}

func TestMatchNetworkStrictProfileAllowsOnlyProxyTuple(t *testing.T) {
	policy := strictProxyPolicy()
	bundle := Bundle{SchemaVersion: SchemaVersion, Policies: []Policy{policy}}
	allowed, err := MatchNetwork(bundle, NetworkObservation{
		Destination: netip.MustParseAddr("192.0.2.10"), Port: 3128, Protocol: ProtocolTCP,
	})
	if err != nil {
		t.Fatalf("MatchNetwork allowed: %v", err)
	}
	if allowed.Decisions[0].Disposition != DispositionAllowed || len(allowed.Hits) != 1 ||
		allowed.Hits[0].RuleKind != "network_allow" || allowed.Hits[0].EffectiveAction != ActionAudit {
		t.Fatalf("allowed result = %+v", allowed)
	}
	denied, err := MatchNetwork(bundle, NetworkObservation{
		Destination: netip.MustParseAddr("192.0.2.11"), Port: 3128, Protocol: ProtocolTCP,
	})
	if err != nil {
		t.Fatalf("MatchNetwork denied: %v", err)
	}
	if denied.Decisions[0].Disposition != DispositionDenied || len(denied.Hits) != 1 {
		t.Fatalf("denied result = %+v", denied)
	}
	hit := denied.Hits[0]
	if hit.RequestedAction != ActionBlock || hit.EffectiveAction != ActionAudit || hit.Enforced {
		t.Fatalf("deny enforcement semantics = %+v", hit)
	}
	if !containsString(hit.Reasons, "enforcement_not_connected") {
		t.Fatalf("deny reasons = %v", hit.Reasons)
	}
}

func TestMatchNetworkDefaultDenyWithoutAllowlistDeniesAll(t *testing.T) {
	policy := strictProxyPolicy()
	policy.Conditions.Network.CIDRs = nil
	policy.Conditions.Network.Ports = nil
	result, err := MatchNetwork(
		Bundle{SchemaVersion: SchemaVersion, Policies: []Policy{policy}},
		NetworkObservation{Destination: netip.MustParseAddr("192.0.2.10"), Port: 3128, Protocol: ProtocolTCP},
	)
	if err != nil {
		t.Fatalf("MatchNetwork: %v", err)
	}
	if result.Decisions[0].Disposition != DispositionDenied {
		t.Fatalf("decision = %+v", result.Decisions[0])
	}
}

func TestMatchNetworkStrictProfileNeverAllowsUDP(t *testing.T) {
	result, err := MatchNetwork(
		Bundle{SchemaVersion: SchemaVersion, Policies: []Policy{strictProxyPolicy()}},
		NetworkObservation{Destination: netip.MustParseAddr("192.0.2.10"), Port: 3128, Protocol: ProtocolUDP},
	)
	if err != nil {
		t.Fatalf("MatchNetwork: %v", err)
	}
	if result.Decisions[0].Disposition != DispositionDenied {
		t.Fatalf("decision = %+v", result.Decisions[0])
	}
}

func TestMatchNetworkExplainsDirectBypassProtocols(t *testing.T) {
	policy := strictProxyPolicy()
	tests := []struct {
		name     string
		port     uint16
		protocol NetworkProtocol
		reason   string
	}{
		{"DNS", 53, ProtocolUDP, "direct_dns_not_allowed"},
		{"DoH or HTTPS", 443, ProtocolTCP, "direct_https_or_doh_not_allowed"},
		{"QUIC", 443, ProtocolUDP, "direct_quic_not_allowed"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result, err := MatchNetwork(
				Bundle{SchemaVersion: SchemaVersion, Policies: []Policy{policy}},
				NetworkObservation{
					Destination: netip.MustParseAddr("198.51.100.8"),
					Port:        test.port, Protocol: test.protocol,
				},
			)
			if err != nil {
				t.Fatalf("MatchNetwork: %v", err)
			}
			if len(result.Hits) != 1 || !containsString(result.Hits[0].Reasons, test.reason) {
				t.Fatalf("hits = %+v", result.Hits)
			}
		})
	}
}

func TestMatchNetworkHostnameNeverGrantsAccess(t *testing.T) {
	result, err := MatchNetwork(
		Bundle{SchemaVersion: SchemaVersion, Policies: []Policy{strictProxyPolicy()}},
		NetworkObservation{
			Destination: netip.MustParseAddr("198.51.100.9"), Port: 443,
			Protocol: ProtocolTCP, ObservedHostname: "proxy.example.test",
		},
	)
	if err != nil {
		t.Fatalf("MatchNetwork: %v", err)
	}
	if result.Decisions[0].Disposition != DispositionDenied ||
		!hasGap(result.Gaps, "dynamic_hostname_observe_only") {
		t.Fatalf("result = %+v", result)
	}
}

func TestNetworkConditionRejectsCIDRMissingFamily(t *testing.T) {
	policy := networkObservePolicy()
	policy.Conditions.Network.Families = []IPFamily{FamilyIPv4}
	policy.Conditions.Network.CIDRs = []string{"2001:db8::/32"}
	err := policy.Validate()
	if err == nil || !strings.Contains(err.Error(), `requires family "ipv6"`) {
		t.Fatalf("Validate error = %v", err)
	}
}

func TestStrictNetworkProfileConfigLoads(t *testing.T) {
	result, err := LoadFile(filepath.Join("..", "..", "configs", "strict-network-profile.yaml"), Limits{})
	if err != nil {
		t.Fatalf("LoadFile: %v", err)
	}
	if len(result.Bundle.Policies) != 1 || result.Bundle.Policies[0].Conditions.Network.Default != NetworkDefaultDeny {
		t.Fatalf("bundle = %+v", result.Bundle)
	}
}

func networkObservePolicy() Policy {
	policy := validPolicy()
	policy.ID = "builtin.net.observe"
	policy.RequestedAction = ActionAudit
	policy.Conditions = Conditions{Network: &NetworkCondition{
		Default: NetworkDefaultObserve,
		CIDRs:   []string{"0.0.0.0/0", "::/0"},
		Families: []IPFamily{
			FamilyIPv4, FamilyIPv6,
		},
	}}
	return policy
}

func strictProxyPolicy() Policy {
	policy := validPolicy()
	policy.ID = "demo.net.strict-proxy"
	policy.Decision = DecisionDeny
	policy.RequestedAction = ActionBlock
	policy.Conditions = Conditions{Network: &NetworkCondition{
		Default:  NetworkDefaultDeny,
		CIDRs:    []string{"192.0.2.10/32"},
		Ports:    []PortRange{{From: 3128, To: 3128}},
		Families: []IPFamily{FamilyIPv4},
	}}
	return policy
}
