package policy

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadFileDefaultPolicies(t *testing.T) {
	result, err := LoadFile(filepath.Join("..", "..", "configs", "default-policies.yaml"), Limits{})
	if err != nil {
		t.Fatalf("LoadFile: %v", err)
	}
	if got := len(result.Bundle.Policies); got != 3 {
		t.Fatalf("policy count = %d, want 3", got)
	}
	if result.Preview.KernelRuleCount != 5 || result.Preview.UserSpaceRuleCount != 2 {
		t.Fatalf("preview counts = kernel %d, user space %d; want 5 and 2",
			result.Preview.KernelRuleCount,
			result.Preview.UserSpaceRuleCount,
		)
	}
	if got := result.Preview.Policies[1].Execution; got != ExecutionMixed {
		t.Fatalf("exec policy class = %q, want %q", got, ExecutionMixed)
	}
	if !result.Preview.Policies[1].FallbackRequired {
		t.Fatal("exec argument matching did not report a required user-space fallback")
	}
}

func TestLoadJSONNormalizesDeprecatedKill(t *testing.T) {
	bundle := Bundle{SchemaVersion: SchemaVersion, Policies: []Policy{validPolicy()}}
	bundle.Policies[0].Decision = DecisionDeny
	bundle.Policies[0].RequestedAction = ActionKill
	data, err := json.Marshal(bundle)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}

	result, err := Load(data, FormatJSON, Limits{})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got := result.Bundle.Policies[0].RequestedAction; got != ActionContain {
		t.Fatalf("requested action = %q, want contain", got)
	}
	if len(result.Diagnostics) != 1 || result.Diagnostics[0].Code != "deprecated_action_kill" {
		t.Fatalf("diagnostics = %+v", result.Diagnostics)
	}
}

func TestLoadRejectsUnknownAndDuplicateFields(t *testing.T) {
	validYAML := validPolicyYAML()
	tests := []struct {
		name   string
		format Format
		input  string
		want   string
	}{
		{
			name:   "unknown YAML field",
			format: FormatYAML,
			input:  strings.Replace(validYAML, "    enabled: true", "    enabled: true\n    surprise: true", 1),
			want:   "field surprise not found",
		},
		{
			name:   "unknown JSON field",
			format: FormatJSON,
			input:  `{"schema_version":1,"policies":[],"surprise":true}`,
			want:   "unknown field",
		},
		{
			name:   "duplicate JSON field",
			format: FormatJSON,
			input:  `{"schema_version":1,"schema_version":1,"policies":[]}`,
			want:   `duplicate object key "schema_version"`,
		},
		{
			name:   "multiple YAML documents",
			format: FormatYAML,
			input:  validYAML + "\n---\nschema_version: 1\npolicies: []\n",
			want:   "multiple documents",
		},
		{
			name:   "multiple JSON values",
			format: FormatJSON,
			input:  `{"schema_version":1,"policies":[]} {}`,
			want:   "multiple documents or values",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := Load([]byte(test.input), test.format, Limits{})
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("Load error = %v, want fragment %q", err, test.want)
			}
		})
	}
}

func TestLoadRequiresExplicitBooleanAndPriority(t *testing.T) {
	for _, field := range []string{"enabled", "priority"} {
		t.Run(field, func(t *testing.T) {
			line := "    " + field + ": "
			input := validPolicyYAML()
			start := strings.Index(input, line)
			if start < 0 {
				t.Fatalf("fixture does not contain %q", line)
			}
			end := strings.IndexByte(input[start:], '\n') + start + 1
			input = input[:start] + input[end:]
			_, err := Load([]byte(input), FormatYAML, Limits{})
			if err == nil || !strings.Contains(err.Error(), field+" is required") {
				t.Fatalf("Load error = %v, want required %s", err, field)
			}
		})
	}
}

func TestLoadEnforcesInputSizeAndFileExtension(t *testing.T) {
	_, err := Load([]byte("12345"), FormatJSON, Limits{MaxFileBytes: 4})
	if err == nil || !strings.Contains(err.Error(), "5 bytes; limit is 4") {
		t.Fatalf("oversize error = %v", err)
	}

	filename := filepath.Join(t.TempDir(), "policies.txt")
	if err := os.WriteFile(filename, []byte(validPolicyYAML()), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	_, err = LoadFile(filename, Limits{})
	if err == nil || !strings.Contains(err.Error(), "unsupported extension") {
		t.Fatalf("extension error = %v", err)
	}
}

func TestLoadRejectsUnsupportedFormat(t *testing.T) {
	_, err := Load([]byte(validPolicyYAML()), Format("toml"), Limits{})
	if err == nil || !strings.Contains(err.Error(), "use json or yaml") {
		t.Fatalf("format error = %v", err)
	}
}

func TestLoadRejectsInvalidUTF8(t *testing.T) {
	input := append([]byte(validPolicyYAML()), 0xff)
	_, err := Load(input, FormatYAML, Limits{})
	if err == nil || !strings.Contains(err.Error(), "valid UTF-8") {
		t.Fatalf("UTF-8 error = %v", err)
	}
}

func validPolicyYAML() string {
	return `schema_version: 1
policies:
  - id: test.policy
    name: Test policy
    enabled: true
    scope:
      type: global
    policy_decision: observe
    requested_action: alert
    priority: 10
    severity: high
    conditions:
      file:
        exact_paths: [/tmp/example]
        access: [read]
`
}
