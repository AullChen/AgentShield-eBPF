package policy

import (
	"errors"
	"fmt"
	"hash/fnv"
	"math"
	"net/netip"
	"slices"
)

var ErrNetworkEnforcementUnsupported = errors.New("network enforcement unsupported")

const (
	NetworkAllowAnyAddress uint32 = 1 << iota
	NetworkAllowAnyPort
)

type NetworkAllowTuple struct {
	AddressFamily uint16
	Port          uint16
	Address       [16]byte
	MatchFlags    uint32
}

type NetworkEnforcementImage struct {
	ProfileID  uint32
	Generation uint32
	PolicyID   uint32
	RuleID     uint32
	Allows     []NetworkAllowTuple
}

// CompileNetworkEnforcement builds the bounded exact-tuple representation
// consumed synchronously by cgroup connect4/connect6. A nil image means no
// applicable block policy. Unsupported policy shapes fail explicitly instead
// of being mislabeled as enforced.
func CompileNetworkEnforcement(bundle Bundle, context EvaluationContext, profileID uint32, generation Generation) (*NetworkEnforcementImage, error) {
	if profileID == 0 {
		return nil, errors.New("network enforcement profile ID must be non-zero")
	}
	if generation.Revision == 0 || generation.Revision > math.MaxUint32 {
		return nil, fmt.Errorf("network enforcement generation revision %d does not fit the kernel ABI", generation.Revision)
	}
	if err := bundle.Validate(); err != nil {
		return nil, fmt.Errorf("validate policy bundle: %w", err)
	}
	selected := selectPolicies(bundle, context, conditionNetwork)
	var blocking []Policy
	for _, policy := range selected.Policies {
		if policy.RequestedAction == ActionBlock {
			blocking = append(blocking, policy)
		}
	}
	if len(blocking) == 0 {
		return nil, nil
	}
	if len(blocking) != 1 {
		return nil, fmt.Errorf("%w: got %d applicable block policies; the first kernel profile supports exactly one", ErrNetworkEnforcementUnsupported, len(blocking))
	}
	policy := blocking[0]
	condition := policy.Conditions.Network
	if condition.Default != NetworkDefaultDeny || policy.Decision != DecisionDeny {
		return nil, fmt.Errorf("%w: policy %q is not a default_deny deny policy", ErrNetworkEnforcementUnsupported, policy.ID)
	}

	addresses, err := enforcementAddresses(*condition)
	if err != nil {
		return nil, fmt.Errorf("%w: policy %q: %v", ErrNetworkEnforcementUnsupported, policy.ID, err)
	}
	ports, err := enforcementPorts(*condition)
	if err != nil {
		return nil, fmt.Errorf("%w: policy %q: %v", ErrNetworkEnforcementUnsupported, policy.ID, err)
	}
	var allows []NetworkAllowTuple
	if len(condition.CIDRs) != 0 || len(condition.Ports) != 0 {
		allows = crossNetworkAllows(addresses, ports, len(condition.CIDRs) == 0, len(condition.Ports) == 0)
	}
	if len(allows) > DefaultLimits().KernelMapCapacity {
		return nil, fmt.Errorf("%w: policy %q emits %d allow tuples; capacity is %d", ErrNetworkEnforcementUnsupported, policy.ID, len(allows), DefaultLimits().KernelMapCapacity)
	}

	registry := make(ruleIDRegistry)
	ruleID, err := registry.add(policy.ID, "network_default", 0)
	if err != nil {
		return nil, err
	}
	return &NetworkEnforcementImage{
		ProfileID:  profileID,
		Generation: uint32(generation.Revision),
		PolicyID:   stablePolicyID(policy.ID),
		RuleID:     ruleID,
		Allows:     allows,
	}, nil
}

type enforcementAddress struct {
	family uint16
	value  [16]byte
}

func enforcementAddresses(condition NetworkCondition) ([]enforcementAddress, error) {
	if len(condition.CIDRs) == 0 {
		addresses := make([]enforcementAddress, 0, len(condition.Families))
		for _, family := range condition.Families {
			if family == FamilyIPv4 {
				addresses = append(addresses, enforcementAddress{family: 2})
			} else {
				addresses = append(addresses, enforcementAddress{family: 10})
			}
		}
		return addresses, nil
	}
	addresses := make([]enforcementAddress, 0, len(condition.CIDRs))
	for _, raw := range condition.CIDRs {
		prefix, _ := netip.ParsePrefix(raw)
		address := prefix.Addr().Unmap()
		if prefix.Bits() != address.BitLen() {
			return nil, fmt.Errorf("CIDR %q is not an exact host prefix", raw)
		}
		entry := enforcementAddress{family: 10}
		if address.Is4() {
			entry.family = 2
			ipv4 := address.As4()
			copy(entry.value[:], ipv4[:])
		} else {
			entry.value = address.As16()
		}
		addresses = append(addresses, entry)
	}
	return addresses, nil
}

func enforcementPorts(condition NetworkCondition) ([]uint16, error) {
	if len(condition.Ports) == 0 {
		return []uint16{0}, nil
	}
	ports := make([]uint16, 0, len(condition.Ports))
	for _, portRange := range condition.Ports {
		if portRange.From != portRange.To {
			return nil, fmt.Errorf("port range %d-%d is not an exact port", portRange.From, portRange.To)
		}
		ports = append(ports, portRange.From)
	}
	return ports, nil
}

func crossNetworkAllows(addresses []enforcementAddress, ports []uint16, anyAddress, anyPort bool) []NetworkAllowTuple {
	if len(addresses) == 0 || len(ports) == 0 {
		return nil
	}
	allows := make([]NetworkAllowTuple, 0, len(addresses)*len(ports))
	seen := make(map[NetworkAllowTuple]struct{}, cap(allows))
	for _, address := range addresses {
		for _, port := range ports {
			tuple := NetworkAllowTuple{AddressFamily: address.family, Port: port, Address: address.value}
			if anyAddress {
				tuple.MatchFlags |= NetworkAllowAnyAddress
			}
			if anyPort {
				tuple.MatchFlags |= NetworkAllowAnyPort
			}
			if _, exists := seen[tuple]; exists {
				continue
			}
			seen[tuple] = struct{}{}
			allows = append(allows, tuple)
		}
	}
	slices.SortFunc(allows, func(first, second NetworkAllowTuple) int {
		if first.AddressFamily != second.AddressFamily {
			return int(first.AddressFamily) - int(second.AddressFamily)
		}
		if comparison := slices.Compare(first.Address[:], second.Address[:]); comparison != 0 {
			return comparison
		}
		if first.Port != second.Port {
			return int(first.Port) - int(second.Port)
		}
		return int(first.MatchFlags) - int(second.MatchFlags)
	})
	return allows
}

func stablePolicyID(policyID string) uint32 {
	hash := fnv.New32a()
	hash.Write([]byte(policyID))
	value := hash.Sum32()
	if value == 0 {
		return 1
	}
	return value
}
