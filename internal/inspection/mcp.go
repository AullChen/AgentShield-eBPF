package inspection

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"path"
	"regexp"
	"strings"
)

var toolName = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,128}$`)

// MCPPolicy describes a local preflight policy, not a complete MCP transport.
// The trusted definition snapshot includes server identity/version, descriptions
// and schemas. A byte change pauses checks until an operator replaces the pin.
type MCPPolicy struct {
	ServerName       string       `json:"server_name"`
	Version          string       `json:"version"`
	DefinitionFile   string       `json:"definition_file"`
	DefinitionSHA256 string       `json:"definition_sha256"`
	Tools            []ToolPolicy `json:"tools"`
}
type ToolPolicy struct {
	Name      string                  `json:"name"`
	Arguments map[string]ArgumentRule `json:"arguments"`
	Required  []string                `json:"required"`
}
type ArgumentRule struct {
	AllowedValues []string `json:"allowed_values,omitempty"`
	PathPrefix    string   `json:"path_prefix,omitempty"`
}

func cleanAbsolute(value string) bool {
	return strings.HasPrefix(value, "/") && path.Clean(value) == value && !strings.ContainsAny(value, "\\\x00")
}

func (checker *Checker) definitions(policy *MCPPolicy) (map[string]bool, error) {
	data, err := checker.ownerRead(policy.DefinitionFile)
	if err != nil || len(data) > MaxBody {
		return nil, errors.New("definition_unavailable")
	}
	digest := sha256.Sum256(data)
	if hex.EncodeToString(digest[:]) != policy.DefinitionSHA256 {
		return nil, errors.New("definition_changed")
	}
	definition, err := decodeObject(data)
	if err != nil || definition["server_name"] != policy.ServerName || definition["version"] != policy.Version {
		return nil, errors.New("definition_identity")
	}
	tools, ok := definition["tools"].([]any)
	if !ok || len(tools) > 128 {
		return nil, errors.New("invalid_definition")
	}
	names := map[string]bool{}
	for _, item := range tools {
		tool, ok := item.(map[string]any)
		if !ok {
			return nil, errors.New("invalid_definition")
		}
		name, ok := tool["name"].(string)
		if !ok || !toolName.MatchString(name) || names[name] {
			return nil, errors.New("invalid_definition")
		}
		if _, ok := tool["description"].(string); !ok {
			return nil, errors.New("invalid_definition")
		}
		if _, ok := tool["inputSchema"].(map[string]any); !ok {
			return nil, errors.New("invalid_definition")
		}
		names[name] = true
	}
	return names, nil
}

func (checker *Checker) validateMCP(policy *MCPPolicy) error {
	if !identifier.MatchString(policy.ServerName) || policy.Version == "" || len(policy.Version) > 128 || !digestPattern.MatchString(policy.DefinitionSHA256) || len(policy.Tools) == 0 || len(policy.Tools) > 128 {
		return errors.New("invalid MCP policy")
	}
	names, err := checker.definitions(policy)
	if err != nil {
		return err
	}
	seen := map[string]bool{}
	for _, tool := range policy.Tools {
		if !toolName.MatchString(tool.Name) || !names[tool.Name] || seen[tool.Name] || len(tool.Arguments) > 32 {
			return errors.New("invalid tool policy")
		}
		seen[tool.Name] = true
		for key, rule := range tool.Arguments {
			if key == "" || len(key) > 128 || (rule.PathPrefix == "") == (len(rule.AllowedValues) == 0) || len(rule.AllowedValues) > 64 {
				return errors.New("invalid argument policy")
			}
			if rule.PathPrefix != "" && (!cleanAbsolute(rule.PathPrefix) || rule.PathPrefix == "/") {
				return errors.New("invalid path policy")
			}
			for _, value := range rule.AllowedValues {
				if value == "" || len(value) > 4096 || strings.ContainsRune(value, 0) {
					return errors.New("invalid allowed value")
				}
			}
		}
		for _, required := range tool.Required {
			if _, ok := tool.Arguments[required]; !ok {
				return errors.New("required argument has no policy")
			}
		}
	}
	return nil
}

func (checker *Checker) checkMCP(policy *MCPPolicy, request map[string]any) error {
	names, err := checker.definitions(policy)
	if err != nil {
		return err
	}
	for key := range request {
		if key != "jsonrpc" && key != "id" && key != "method" && key != "params" {
			return errors.New("unsupported_mcp_request")
		}
	}
	if request["jsonrpc"] != "2.0" || request["method"] != "tools/call" {
		return errors.New("unsupported_mcp_request")
	}
	switch id := request["id"].(type) {
	case string:
		if id == "" || len(id) > 128 {
			return errors.New("invalid_request_id")
		}
	case json.Number:
		if len(id) > 128 {
			return errors.New("invalid_request_id")
		}
	default:
		return errors.New("invalid_request_id")
	}
	params, ok := request["params"].(map[string]any)
	if !ok || len(params) != 2 {
		return errors.New("invalid_tool_parameters")
	}
	name, ok := params["name"].(string)
	if !ok || !names[name] {
		return errors.New("tool_denied")
	}
	arguments, ok := params["arguments"].(map[string]any)
	if !ok {
		return errors.New("invalid_tool_parameters")
	}
	var selected *ToolPolicy
	for index := range policy.Tools {
		if policy.Tools[index].Name == name {
			selected = &policy.Tools[index]
			break
		}
	}
	if selected == nil {
		return errors.New("tool_denied")
	}
	for _, required := range selected.Required {
		if _, ok := arguments[required]; !ok {
			return errors.New("argument_required")
		}
	}
	for key, value := range arguments {
		rule, ok := selected.Arguments[key]
		if !ok {
			return errors.New("argument_denied")
		}
		text, ok := value.(string)
		if !ok || len(text) > 4096 {
			return errors.New("argument_denied")
		}
		if rule.PathPrefix != "" {
			if !cleanAbsolute(text) || text != rule.PathPrefix && !strings.HasPrefix(text, rule.PathPrefix+"/") {
				return errors.New("argument_out_of_range")
			}
		} else {
			allowed := false
			for _, value := range rule.AllowedValues {
				if text == value {
					allowed = true
					break
				}
			}
			if !allowed {
				return errors.New("argument_out_of_range")
			}
		}
	}
	return nil
}
