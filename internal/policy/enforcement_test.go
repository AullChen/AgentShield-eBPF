package policy

import (
	"errors"
	"testing"
)

func TestCompileNetworkEnforcementBuildsExactProxyTuple(t *testing.T) {
	policy := strictProxyPolicy()
	image, err := CompileNetworkEnforcement(
		Bundle{SchemaVersion: SchemaVersion, Policies: []Policy{policy}},
		EvaluationContext{},
		7,
		Generation{Revision: 9, Bank: BankA},
	)
	if err != nil {
		t.Fatalf("CompileNetworkEnforcement() error = %v", err)
	}
	if image == nil || image.ProfileID != 7 || image.Generation != 9 || image.PolicyID == 0 || image.RuleID == 0 {
		t.Fatalf("image = %+v", image)
	}
	if len(image.Allows) != 1 {
		t.Fatalf("allow tuple count = %d, want 1", len(image.Allows))
	}
	tuple := image.Allows[0]
	if tuple.AddressFamily != 2 || tuple.Port != 3128 || tuple.Address[0] != 192 || tuple.Address[1] != 0 || tuple.Address[2] != 2 || tuple.Address[3] != 10 {
		t.Fatalf("allow tuple = %+v", tuple)
	}
}

func TestCompileNetworkEnforcementEmptyAllowlistDeniesAll(t *testing.T) {
	policy := strictProxyPolicy()
	policy.Conditions.Network.CIDRs = nil
	policy.Conditions.Network.Ports = nil
	image, err := CompileNetworkEnforcement(
		Bundle{SchemaVersion: SchemaVersion, Policies: []Policy{policy}},
		EvaluationContext{}, 1, Generation{Revision: 1, Bank: BankA},
	)
	if err != nil {
		t.Fatalf("CompileNetworkEnforcement() error = %v", err)
	}
	if image == nil || len(image.Allows) != 0 {
		t.Fatalf("image = %+v, want deny-all profile without allow tuples", image)
	}
}

func TestCompileNetworkEnforcementUsesExplicitWildcardFlags(t *testing.T) {
	policy := strictProxyPolicy()
	policy.Conditions.Network.CIDRs = nil
	image, err := CompileNetworkEnforcement(
		Bundle{SchemaVersion: SchemaVersion, Policies: []Policy{policy}},
		EvaluationContext{}, 1, Generation{Revision: 1, Bank: BankA},
	)
	if err != nil || image == nil || len(image.Allows) != 1 || image.Allows[0].MatchFlags != NetworkAllowAnyAddress {
		t.Fatalf("any-address image = %+v, error = %v", image, err)
	}

	policy = strictProxyPolicy()
	policy.Conditions.Network.CIDRs = []string{"0.0.0.0/32"}
	image, err = CompileNetworkEnforcement(
		Bundle{SchemaVersion: SchemaVersion, Policies: []Policy{policy}},
		EvaluationContext{}, 1, Generation{Revision: 1, Bank: BankA},
	)
	if err != nil || image == nil || len(image.Allows) != 1 || image.Allows[0].MatchFlags != 0 {
		t.Fatalf("exact zero-address image = %+v, error = %v", image, err)
	}

	policy = strictProxyPolicy()
	policy.Conditions.Network.Ports = nil
	image, err = CompileNetworkEnforcement(
		Bundle{SchemaVersion: SchemaVersion, Policies: []Policy{policy}},
		EvaluationContext{}, 1, Generation{Revision: 1, Bank: BankA},
	)
	if err != nil || image == nil || len(image.Allows) != 1 || image.Allows[0].MatchFlags != NetworkAllowAnyPort {
		t.Fatalf("any-port image = %+v, error = %v", image, err)
	}
}

func TestCompileNetworkEnforcementRejectsShapesNotRepresentableByKernelMap(t *testing.T) {
	policy := strictProxyPolicy()
	policy.Conditions.Network.CIDRs = []string{"192.0.2.0/24"}
	_, err := CompileNetworkEnforcement(
		Bundle{SchemaVersion: SchemaVersion, Policies: []Policy{policy}},
		EvaluationContext{}, 1, Generation{Revision: 1, Bank: BankA},
	)
	if !errors.Is(err, ErrNetworkEnforcementUnsupported) {
		t.Fatalf("non-host CIDR error = %v, want ErrNetworkEnforcementUnsupported", err)
	}

	first := strictProxyPolicy()
	second := strictProxyPolicy()
	second.ID = "second"
	_, err = CompileNetworkEnforcement(
		Bundle{SchemaVersion: SchemaVersion, Policies: []Policy{first, second}},
		EvaluationContext{}, 1, Generation{Revision: 1, Bank: BankA},
	)
	if !errors.Is(err, ErrNetworkEnforcementUnsupported) {
		t.Fatalf("multi-policy error = %v, want ErrNetworkEnforcementUnsupported", err)
	}
}

func TestCompileNetworkEnforcementReturnsNilWithoutApplicableBlockPolicy(t *testing.T) {
	policy := networkObservePolicy()
	image, err := CompileNetworkEnforcement(
		Bundle{SchemaVersion: SchemaVersion, Policies: []Policy{policy}},
		EvaluationContext{}, 1, Generation{Revision: 1, Bank: BankA},
	)
	if err != nil || image != nil {
		t.Fatalf("image = %+v, error = %v", image, err)
	}
}

func TestCompileNetworkEnforcementRejectsBlockWhenAnotherPolicyCanWin(t *testing.T) {
	block := strictProxyPolicy()
	block.Priority = 1
	observe := networkObservePolicy()
	observe.Priority = 1000

	_, err := CompileNetworkEnforcement(
		Bundle{SchemaVersion: SchemaVersion, Policies: []Policy{block, observe}},
		EvaluationContext{}, 1, Generation{Revision: 1, Bank: BankA},
	)
	if !errors.Is(err, ErrNetworkEnforcementUnsupported) {
		t.Fatalf("conflicting-policy error = %v, want ErrNetworkEnforcementUnsupported", err)
	}
}
