package policy

import (
	"strings"
	"testing"
)

func TestPreviewCompileExplainsUserSpaceFallback(t *testing.T) {
	policy := validPolicy()
	policy.Conditions = Conditions{File: &FileCondition{
		Prefixes: []string{"/tmp/work/"},
		Access:   []FileAccess{FileWrite},
	}}
	bundle := Bundle{SchemaVersion: SchemaVersion, Policies: []Policy{policy}}

	preview, err := PreviewCompile(bundle, Limits{})
	if err != nil {
		t.Fatalf("PreviewCompile: %v", err)
	}
	got := preview.Policies[0]
	if got.Execution != ExecutionUserSpaceOnly || !got.FallbackRequired {
		t.Fatalf("policy preview = %+v", got)
	}
	if len(got.Reasons) != 1 || got.Reasons[0] != "file_prefix_requires_user_space" {
		t.Fatalf("fallback reasons = %v", got.Reasons)
	}
}

func TestPreviewCompileTreatsArgumentMetacharactersLiterally(t *testing.T) {
	policy := validPolicy()
	policy.Conditions = Conditions{Exec: &ExecCondition{ArgContains: []string{"test [ -f file ]?"}}}
	bundle := Bundle{SchemaVersion: SchemaVersion, Policies: []Policy{policy}}

	preview, err := PreviewCompile(bundle, Limits{MaxGlobMetacharacters: 1})
	if err != nil {
		t.Fatalf("PreviewCompile: %v", err)
	}
	if got := preview.Policies[0]; got.Execution != ExecutionUserSpaceOnly || got.UserSpaceRuleCount != 1 {
		t.Fatalf("argument preview = %+v", got)
	}
}

func TestPreviewCompileRejectsUserSpaceBlock(t *testing.T) {
	policy := validPolicy()
	policy.Decision = DecisionDeny
	policy.RequestedAction = ActionBlock
	policy.Conditions = Conditions{Exec: &ExecCondition{ArgContains: []string{"curl | sh"}}}
	bundle := Bundle{SchemaVersion: SchemaVersion, Policies: []Policy{policy}}

	preview, err := PreviewCompile(bundle, Limits{})
	if err == nil || !strings.Contains(err.Error(), "requests block but requires user-space evaluation") {
		t.Fatalf("PreviewCompile error = %v", err)
	}
	if got := preview.Policies[0].Reasons; len(got) != 1 || got[0] != "exec_argument_requires_user_space" {
		t.Fatalf("partial preview reasons = %v", got)
	}
}

func TestPreviewCompileCountsMixedAndDisabledPolicies(t *testing.T) {
	mixed := validPolicy()
	mixed.ID = "mixed"
	mixed.Conditions = Conditions{File: &FileCondition{
		ExactPaths: []string{"/etc/passwd", "relative/*.key"},
		Access:     []FileAccess{FileRead},
	}}
	disabled := validPolicy()
	disabled.ID = "disabled"
	disabled.Enabled = false
	bundle := Bundle{SchemaVersion: SchemaVersion, Policies: []Policy{mixed, disabled}}

	preview, err := PreviewCompile(bundle, Limits{})
	if err != nil {
		t.Fatalf("PreviewCompile: %v", err)
	}
	if preview.KernelRuleCount != 1 || preview.UserSpaceRuleCount != 1 {
		t.Fatalf("preview counts = %+v", preview)
	}
	if preview.Policies[0].Execution != ExecutionMixed {
		t.Fatalf("mixed class = %q", preview.Policies[0].Execution)
	}
	if preview.Policies[1].Execution != ExecutionDisabled ||
		preview.Policies[1].KernelRuleCount != 0 || preview.Policies[1].UserSpaceRuleCount != 0 {
		t.Fatalf("disabled preview = %+v", preview.Policies[1])
	}
}

func TestPreviewCompileEnforcesCapacities(t *testing.T) {
	tests := []struct {
		name   string
		policy Policy
		limits Limits
		want   string
	}{
		{
			name:   "kernel map",
			policy: validPolicy(),
			limits: Limits{KernelMapCapacity: 1},
			want:   "kernel rule estimate 2 exceeds map capacity 1",
		},
		{
			name: "user space",
			policy: func() Policy {
				policy := validPolicy()
				policy.Conditions = Conditions{Exec: &ExecCondition{ArgContains: []string{"one", "two"}}}
				return policy
			}(),
			limits: Limits{MaxUserSpaceRules: 1},
			want:   "user-space rule estimate 2 exceeds capacity 1",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if test.name == "kernel map" {
				test.policy.Conditions.File.ExactPaths = append(test.policy.Conditions.File.ExactPaths, "/tmp/second")
			}
			bundle := Bundle{SchemaVersion: SchemaVersion, Policies: []Policy{test.policy}}
			_, err := PreviewCompile(bundle, test.limits)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("PreviewCompile error = %v, want fragment %q", err, test.want)
			}
		})
	}
}

func TestPreviewCompileEnforcesPolicyLimits(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*Policy)
		limits Limits
		want   string
	}{
		{
			name: "string length",
			mutate: func(policy *Policy) {
				policy.ID = "id"
				policy.Name = "12345"
			},
			limits: Limits{MaxStringBytes: 4},
			want:   "name: got 5 bytes, limit is 4",
		},
		{
			name: "condition values",
			mutate: func(policy *Policy) {
				policy.Conditions.File.ExactPaths = []string{"/one", "/two"}
			},
			limits: Limits{MaxConditionValues: 2},
			want:   "conditions: got 3 values, limit is 2",
		},
		{
			name: "glob complexity",
			mutate: func(policy *Policy) {
				policy.Conditions.File.ExactPaths = []string{"/tmp/**/secret?.*"}
			},
			limits: Limits{MaxGlobMetacharacters: 3},
			want:   "has 4 metacharacters, limit is 3",
		},
		{
			name: "invalid glob",
			mutate: func(policy *Policy) {
				policy.Conditions.File.ExactPaths = []string{"/tmp/[broken"}
			},
			limits: Limits{},
			want:   "condition glob",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			policy := validPolicy()
			test.mutate(&policy)
			bundle := Bundle{SchemaVersion: SchemaVersion, Policies: []Policy{policy}}
			_, err := PreviewCompile(bundle, test.limits)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("PreviewCompile error = %v, want fragment %q", err, test.want)
			}
		})
	}
}

func TestPreviewCompileEnforcesPolicyCount(t *testing.T) {
	first := validPolicy()
	first.ID = "first"
	second := validPolicy()
	second.ID = "second"
	bundle := Bundle{SchemaVersion: SchemaVersion, Policies: []Policy{first, second}}
	_, err := PreviewCompile(bundle, Limits{MaxPolicies: 1})
	if err == nil || !strings.Contains(err.Error(), "got 2, limit is 1") {
		t.Fatalf("PreviewCompile error = %v", err)
	}
}
