package policy

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestValidPolicyConditionKinds(t *testing.T) {
	tests := []struct {
		name       string
		conditions Conditions
	}{
		{
			name: "file",
			conditions: Conditions{File: &FileCondition{
				ExactPaths: []string{"/demo-secrets/example-token"},
				Access:     []FileAccess{FileRead},
			}},
		},
		{
			name: "exec",
			conditions: Conditions{Exec: &ExecCondition{
				Executables: []string{"sh", "bash"},
				ArgContains: []string{"rm -rf"},
			}},
		},
		{
			name: "network",
			conditions: Conditions{Network: &NetworkCondition{
				Default:  NetworkDefaultObserve,
				CIDRs:    []string{"0.0.0.0/0", "::/0"},
				Ports:    []PortRange{{From: 1, To: 65535}},
				Families: []IPFamily{FamilyIPv4, FamilyIPv6},
			}},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			policy := validPolicy()
			policy.Conditions = test.conditions
			if err := policy.Validate(); err != nil {
				t.Fatalf("Validate: %v", err)
			}
		})
	}
}

func TestDecisionActionMatrix(t *testing.T) {
	actions := []Action{ActionAudit, ActionAlert, ActionBlock, ActionContain}
	allowed := map[Decision]map[Action]bool{
		DecisionObserve: {ActionAudit: true, ActionAlert: true},
		DecisionAllow:   {ActionAudit: true},
		DecisionDeny: {
			ActionAudit: true, ActionAlert: true, ActionBlock: true, ActionContain: true,
		},
	}
	for _, decision := range []Decision{DecisionObserve, DecisionAllow, DecisionDeny} {
		for _, action := range actions {
			t.Run(string(decision)+"/"+string(action), func(t *testing.T) {
				policy := validPolicy()
				policy.Decision = decision
				policy.RequestedAction = action
				err := policy.Validate()
				if allowed[decision][action] && err != nil {
					t.Fatalf("valid combination rejected: %v", err)
				}
				if !allowed[decision][action] && err == nil {
					t.Fatal("invalid combination accepted")
				}
			})
		}
	}
}

func TestKillAliasIsNormalizedWithDiagnostic(t *testing.T) {
	bundle := Bundle{
		SchemaVersion: SchemaVersion,
		Policies:      []Policy{validPolicy()},
	}
	bundle.Policies[0].Decision = DecisionDeny
	bundle.Policies[0].RequestedAction = ActionKill

	diagnostics, err := bundle.NormalizeAndValidate()
	if err != nil {
		t.Fatalf("NormalizeAndValidate: %v", err)
	}
	if len(diagnostics) != 1 || diagnostics[0].Code != "deprecated_action_kill" {
		t.Fatalf("diagnostics = %+v", diagnostics)
	}
	if bundle.Policies[0].RequestedAction != ActionContain {
		t.Fatalf("normalized action = %q, want contain", bundle.Policies[0].RequestedAction)
	}
	encoded, err := json.Marshal(bundle)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	if strings.Contains(string(encoded), `"kill"`) || !strings.Contains(string(encoded), `"contain"`) {
		t.Fatalf("normalized JSON = %s", encoded)
	}
}

func TestBundleRejectsInvalidSchemaAndDuplicateIDs(t *testing.T) {
	bundle := Bundle{
		SchemaVersion: SchemaVersion + 1,
		Policies:      []Policy{validPolicy(), validPolicy()},
	}
	err := bundle.Validate()
	if err == nil {
		t.Fatal("invalid bundle was accepted")
	}
	for _, fragment := range []string{"schema_version", "duplicate policy ID"} {
		if !strings.Contains(err.Error(), fragment) {
			t.Fatalf("error %q does not contain %q", err, fragment)
		}
	}
}

func TestScopeValidation(t *testing.T) {
	valid := []Scope{
		{Type: ScopeGlobal},
		{Type: ScopeRun, RunID: "run-1"},
		{Type: ScopeCgroup, CgroupID: "18446744073709551615"},
		{Type: ScopeLabels, LabelSelector: map[string]string{"purpose": "demo"}},
	}
	for _, scope := range valid {
		if err := scope.Validate(); err != nil {
			t.Fatalf("Validate(%+v): %v", scope, err)
		}
	}
	invalid := []Scope{
		{},
		{Type: ScopeGlobal, RunID: "run-1"},
		{Type: ScopeRun},
		{Type: ScopeCgroup, CgroupID: "0"},
		{Type: ScopeCgroup, CgroupID: "not-decimal"},
		{Type: ScopeLabels, LabelSelector: map[string]string{}},
		{Type: ScopeLabels, LabelSelector: map[string]string{"purpose": ""}},
	}
	for _, scope := range invalid {
		if err := scope.Validate(); err == nil {
			t.Fatalf("invalid scope accepted: %+v", scope)
		}
	}
}

func TestConditionsSelectExactlyOneKind(t *testing.T) {
	for _, conditions := range []Conditions{
		{},
		{
			File: &FileCondition{ExactPaths: []string{"/tmp/a"}, Access: []FileAccess{FileRead}},
			Exec: &ExecCondition{Executables: []string{"sh"}},
		},
	} {
		if err := conditions.Validate(); err == nil {
			t.Fatalf("invalid conditions accepted: %+v", conditions)
		}
	}
}

func TestConditionValidationRejectsInvalidValues(t *testing.T) {
	tests := []Conditions{
		{File: &FileCondition{Access: []FileAccess{FileRead}}},
		{File: &FileCondition{ExactPaths: []string{"/tmp/a"}}},
		{File: &FileCondition{ExactPaths: []string{"/tmp/a"}, Access: []FileAccess{"rename"}}},
		{File: &FileCondition{ExactPaths: []string{"/tmp/a"}, Access: []FileAccess{FileRead, FileRead}}},
		{Exec: &ExecCondition{}},
		{Network: &NetworkCondition{Default: NetworkDefaultObserve, Families: []IPFamily{FamilyIPv4}, CIDRs: []string{"invalid"}}},
		{Network: &NetworkCondition{Default: NetworkDefaultObserve, Families: []IPFamily{FamilyIPv4}, Ports: []PortRange{{From: 90, To: 80}}}},
		{Network: &NetworkCondition{Default: "implicit", Families: []IPFamily{FamilyIPv4}}},
		{Network: &NetworkCondition{Default: NetworkDefaultObserve}},
		{Network: &NetworkCondition{Default: NetworkDefaultObserve, Families: []IPFamily{FamilyIPv4, FamilyIPv4}}},
	}
	for _, conditions := range tests {
		if err := conditions.Validate(); err == nil {
			t.Fatalf("invalid condition accepted: %+v", conditions)
		}
	}
}

func TestHigherPrecedenceUsesScopeThenPriorityThenID(t *testing.T) {
	globalHighPriority := validPolicy()
	globalHighPriority.ID = "policy-z"
	globalHighPriority.Priority = 1000

	runLowPriority := validPolicy()
	runLowPriority.ID = "policy-z"
	runLowPriority.Scope = Scope{Type: ScopeRun, RunID: "run-1"}
	runLowPriority.Priority = -1000
	if !HigherPrecedence(runLowPriority, globalHighPriority) {
		t.Fatal("more specific Run scope did not override global priority")
	}

	globalHigherPriority := validPolicy()
	globalHigherPriority.ID = "policy-z"
	globalHigherPriority.Priority = 2
	globalLowerPriority := validPolicy()
	globalLowerPriority.ID = "policy-a"
	globalLowerPriority.Priority = 1
	if !HigherPrecedence(globalHigherPriority, globalLowerPriority) {
		t.Fatal("higher numeric priority did not win at equal scope")
	}

	stableFirst := validPolicy()
	stableFirst.ID = "policy-a"
	stableSecond := validPolicy()
	stableSecond.ID = "policy-b"
	if !HigherPrecedence(stableFirst, stableSecond) {
		t.Fatal("lexically stable policy ID did not break an exact tie")
	}
}

func validPolicy() Policy {
	return Policy{
		ID:              "builtin.file.demo-secret",
		Name:            "Demo secret access",
		Enabled:         true,
		Scope:           Scope{Type: ScopeGlobal},
		Decision:        DecisionObserve,
		RequestedAction: ActionAlert,
		Priority:        100,
		Severity:        SeverityHigh,
		Conditions: Conditions{File: &FileCondition{
			ExactPaths: []string{"/demo-secrets/example-token"},
			Access:     []FileAccess{FileRead},
		}},
	}
}
