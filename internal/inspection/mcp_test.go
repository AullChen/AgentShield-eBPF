package inspection

import (
	"strings"
	"testing"
)

func TestMCPDefinitionAndArgumentPinning(t *testing.T) {
	c, _ := testChecker(t)
	definition := `{"server_name":"local-files","version":"1","tools":[{"name":"read_file","description":"Read approved file","inputSchema":{"type":"object"},"annotations":{"readOnlyHint":true}},{"name":"delete_file","description":"Delete","inputSchema":{"type":"object"}}]}`
	c.ownerRead = func(string) ([]byte, error) { return []byte(definition), nil }
	policy := &MCPPolicy{ServerName: "local-files", Version: "1", DefinitionFile: "trusted", DefinitionSHA256: digest(definition), Tools: []ToolPolicy{{Name: "read_file", Arguments: map[string]ArgumentRule{"path": {PathPrefix: "/workspace"}, "domain": {AllowedValues: []string{"approved.test"}}}, Required: []string{"path"}}}}
	if err := c.validateMCP(policy); err != nil {
		t.Fatal(err)
	}
	c.routes["files"] = Route{ID: "files", Kind: "mcp", MCP: policy}
	valid := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"/workspace/main.go","domain":"approved.test"}}}`
	if check(c, "files", valid).Code != 403 {
		t.Fatal("unapproved MCP call checked")
	}
	approve(t, c, "files", valid)
	if check(c, "files", strings.Replace(valid, "main.go", "other.go", 1)).Code != 403 {
		t.Fatal("changed arguments reused approval")
	}
	if check(c, "files", valid).Code != 200 {
		t.Fatal("valid approved call failed")
	}
	for _, invalid := range []string{
		strings.Replace(valid, "/workspace/main.go", "/workspace/../private/key", 1),
		strings.Replace(valid, "/workspace/main.go", "/workspace-other/key", 1),
		strings.Replace(valid, "approved.test", "evil.test", 1),
		strings.Replace(valid, "read_file", "delete_file", 1),
		strings.Replace(valid, `"path":"/workspace/main.go",`, "", 1),
		strings.Replace(valid, `"domain":"approved.test"`, `"extra":"value"`, 1),
		strings.Replace(valid, `"method":"tools/call"`, `"method":"tools/list"`, 1),
	} {
		approve(t, c, "files", invalid)
		if check(c, "files", invalid).Code < 400 {
			t.Fatal("invalid MCP parameters checked")
		}
	}
	approve(t, c, "files", valid)
	definition = strings.Replace(definition, "Read approved file", "Changed description", 1)
	w := check(c, "files", valid)
	if w.Code != 403 || !strings.Contains(w.Body.String(), "definition_changed") {
		t.Fatal("tool definition changed without reapproval")
	}
}

func TestMCPAnnotationsDoNotGrantPermission(t *testing.T) {
	c, _ := testChecker(t)
	definition := `{"server_name":"files","version":"1","tools":[{"name":"delete","description":"Unsafe","inputSchema":{},"annotations":{"readOnlyHint":true}}]}`
	c.ownerRead = func(string) ([]byte, error) { return []byte(definition), nil }
	policy := &MCPPolicy{ServerName: "files", Version: "1", DefinitionFile: "trusted", DefinitionSHA256: digest(definition), Tools: []ToolPolicy{{Name: "delete", Arguments: map[string]ArgumentRule{"path": {PathPrefix: "/workspace"}}, Required: []string{"path"}}}}
	c.routes["files"] = Route{ID: "files", Kind: "mcp", MCP: policy}
	body := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"delete","arguments":{"path":"/workspace/main.go"}}}`
	if check(c, "files", body).Code != 403 {
		t.Fatal("readOnlyHint bypassed approval")
	}
}
