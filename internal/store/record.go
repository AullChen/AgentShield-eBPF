package store

import (
	"encoding/json"
	"errors"
	"regexp"
	"sort"
	"strings"
)

type Source string

const (
	SourceAgentClaim        Source = "agent_claim"
	SourceKernelFact        Source = "kernel_fact"
	SourcePolicyDecision    Source = "policy_decision"
	SourceContainmentResult Source = "containment_result"
	SourceDiagnostic        Source = "diagnostic"
)

type Record struct {
	ID                string            `json:"id"`
	RecordType        string            `json:"record_type"`
	RunID             string            `json:"run_id,omitempty"`
	Source            Source            `json:"source"`
	ServerMonotonicNS uint64            `json:"server_monotonic_ns"`
	ServerUnixNS      uint64            `json:"server_unix_ns"`
	InstanceID        uint64            `json:"instance_id,omitempty"`
	ScopeCookie       uint64            `json:"scope_cookie,omitempty"`
	Severity          string            `json:"severity,omitempty"`
	Summary           string            `json:"summary,omitempty"`
	Labels            map[string]string `json:"labels,omitempty"`
	Payload           json.RawMessage   `json:"payload,omitempty"`
}

func (record Record) validate() error {
	if record.ID == "" || len(record.ID) > 128 || record.RecordType == "" || len(record.RecordType) > 64 {
		return errors.New("record identity is invalid")
	}
	for _, value := range []string{record.ID, record.RecordType, record.RunID, record.Severity, record.Summary} {
		if strings.IndexByte(value, 0) >= 0 {
			return errors.New("record text contains a NUL byte")
		}
	}
	switch record.Source {
	case SourceAgentClaim, SourceKernelFact, SourcePolicyDecision, SourceContainmentResult, SourceDiagnostic:
	default:
		return errors.New("record source is invalid")
	}
	if record.ServerMonotonicNS == 0 || record.ServerUnixNS == 0 || len(record.Summary) > 4096 || len(record.Labels) > 32 {
		return errors.New("record exceeds limits")
	}
	if len(record.Payload) > 64<<10 || len(record.Payload) != 0 && !json.Valid(record.Payload) {
		return errors.New("record payload is invalid or exceeds limits")
	}
	for key, value := range record.Labels {
		if key == "" || len(key) > 128 || len(value) > 1024 || strings.IndexByte(key, 0) >= 0 || strings.IndexByte(value, 0) >= 0 {
			return errors.New("record labels exceed limits")
		}
	}
	return nil
}

var credentialPattern = regexp.MustCompile(`(?i)(bearer\s+|(?:token|api[_-]?key|access[_-]?token|refresh[_-]?token|client[_-]?secret|password|passwd|secret|authorization|cookie|aws_secret_access_key)\s*[=:]\s*)[^\s,;]{4,}`)

type Redactor struct {
	values []string
}

func NewRedactor(sensitiveValues []string) Redactor {
	values := make([]string, 0, len(sensitiveValues))
	for _, value := range sensitiveValues {
		if len(value) >= 4 {
			values = append(values, value)
		}
	}
	sort.Slice(values, func(i, j int) bool { return len(values[i]) > len(values[j]) })
	return Redactor{values: values}
}

func (redactor Redactor) Apply(record Record) (Record, error) {
	if err := record.validate(); err != nil {
		return Record{}, err
	}
	record.Summary = redactor.text(record.Summary)
	if record.Labels != nil {
		labels := make(map[string]string, len(record.Labels))
		for key, value := range record.Labels {
			if sensitiveLabelKey(key) {
				labels[key] = "[REDACTED]"
			} else {
				labels[key] = redactor.text(value)
			}
		}
		record.Labels = labels
	}
	if len(record.Payload) != 0 {
		var value any
		decoder := json.NewDecoder(strings.NewReader(string(record.Payload)))
		decoder.UseNumber()
		if err := decoder.Decode(&value); err != nil {
			return Record{}, err
		}
		if err := redactor.scrubJSON(value, 0); err != nil {
			return Record{}, err
		}
		payload, err := json.Marshal(value)
		if err != nil || len(payload) > 64<<10 {
			return Record{}, errors.New("sanitized record payload exceeds limits")
		}
		record.Payload = payload
	}
	return record, nil
}

func (redactor Redactor) scrubJSON(value any, depth int) error {
	if depth > 32 {
		return errors.New("record payload nesting exceeds limits")
	}
	switch typed := value.(type) {
	case map[string]any:
		for key, child := range typed {
			if sensitiveLabelKey(key) || strings.EqualFold(key, "argv") {
				typed[key] = "[REDACTED]"
			} else if text, ok := child.(string); ok {
				typed[key] = redactor.text(text)
			} else if err := redactor.scrubJSON(child, depth+1); err != nil {
				return err
			}
		}
	case []any:
		for index, child := range typed {
			if text, ok := child.(string); ok {
				typed[index] = redactor.text(text)
			} else if err := redactor.scrubJSON(child, depth+1); err != nil {
				return err
			}
		}
	}
	return nil
}

func sensitiveLabelKey(key string) bool {
	normalized := strings.ToLower(key)
	normalized = strings.NewReplacer("-", "", "_", "", ".", "").Replace(normalized)
	for _, suffix := range []string{"prompt", "token", "authorization", "password", "passwd", "secret", "apikey", "accesskey", "clientsecret", "cookie", "privatekey", "credential", "credentials"} {
		if strings.HasSuffix(normalized, suffix) {
			return true
		}
	}
	return false
}

func (redactor Redactor) text(value string) string {
	value = credentialPattern.ReplaceAllString(value, "[REDACTED]")
	for _, secret := range redactor.values {
		value = strings.ReplaceAll(value, secret, "[REDACTED]")
	}
	return value
}

func labelsJSON(labels map[string]string) string {
	if labels == nil {
		return "{}"
	}
	encoded, _ := json.Marshal(labels)
	return string(encoded)
}
