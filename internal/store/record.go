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
}

func (record Record) validate() error {
	if record.ID == "" || len(record.ID) > 128 || record.RecordType == "" || len(record.RecordType) > 64 {
		return errors.New("record identity is invalid")
	}
	switch record.Source {
	case SourceAgentClaim, SourceKernelFact, SourcePolicyDecision, SourceContainmentResult, SourceDiagnostic:
	default:
		return errors.New("record source is invalid")
	}
	if record.ServerMonotonicNS == 0 || record.ServerUnixNS == 0 || len(record.Summary) > 4096 || len(record.Labels) > 32 {
		return errors.New("record exceeds limits")
	}
	for key, value := range record.Labels {
		if key == "" || len(key) > 128 || len(value) > 1024 {
			return errors.New("record labels exceed limits")
		}
	}
	return nil
}

var credentialPattern = regexp.MustCompile(`(?i)(bearer\s+|token[=:]\s*|secret[=:]\s*|password[=:]\s*)[^\s,;]{4,}`)

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
			labels[key] = redactor.text(value)
		}
		record.Labels = labels
	}
	return record, nil
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
