package stream

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
)

const maxJSONLineBytes = maxPayloadBytes

var textCredentialPattern = regexp.MustCompile(`(?i)(bearer\s+|(?:token|api[_-]?key|access[_-]?token|refresh[_-]?token|client[_-]?secret|password|passwd|secret|authorization|cookie|aws_secret_access_key)\s*[=:]\s*)[^\s,;]{4,}`)

type PublishedRecord struct {
	RunID          string
	KernelFact     bool
	PolicyDecision bool
	Blocked        bool
	DroppedType    string
	DroppedCount   uint64
}

type JSONLineSinkOptions struct {
	RunID           string
	SensitiveValues []string
	OnPublished     func(PublishedRecord)
	OnError         func(error)
}

type JSONLineSink struct {
	mu          sync.Mutex
	hub         *Hub
	options     JSONLineSinkOptions
	buffer      []byte
	discardLine bool
	secrets     []string
}

type recordHeader struct {
	RecordType                string `json:"record_type"`
	EventTypeName             string `json:"event_type_name"`
	ActionName                string `json:"action_name"`
	ActionResultName          string `json:"action_result_name"`
	ServerReceivedMonotonicNS string `json:"server_received_monotonic_ns"`
	ServerReceivedUnixNS      string `json:"server_received_unix_ns"`
	DroppedEventTypeName      string `json:"dropped_event_type_name"`
	DroppedCount              string `json:"dropped_count"`
}

func NewJSONLineSink(hub *Hub, options JSONLineSinkOptions) (*JSONLineSink, error) {
	if hub == nil || options.RunID == "" || len(options.RunID) > 128 {
		return nil, errors.New("JSON stream sink requires a hub and Run ID")
	}
	secrets := make([]string, 0, len(options.SensitiveValues))
	for _, secret := range options.SensitiveValues {
		if len(secret) >= 4 {
			secrets = append(secrets, secret)
		}
	}
	slices.SortFunc(secrets, func(left, right string) int { return len(right) - len(left) })
	return &JSONLineSink{hub: hub, options: options, secrets: secrets}, nil
}

func (sink *JSONLineSink) Write(input []byte) (int, error) {
	sink.mu.Lock()
	defer sink.mu.Unlock()

	remaining := input
	for len(remaining) > 0 {
		newline := bytes.IndexByte(remaining, '\n')
		chunk := remaining
		complete := false
		if newline >= 0 {
			chunk = remaining[:newline]
			remaining = remaining[newline+1:]
			complete = true
		} else {
			remaining = nil
		}

		if !sink.discardLine {
			if len(sink.buffer)+len(chunk) > maxJSONLineBytes {
				sink.buffer = sink.buffer[:0]
				sink.discardLine = true
				sink.report(errors.New("stream JSON line exceeded 64 KiB"))
			} else {
				sink.buffer = append(sink.buffer, chunk...)
			}
		}
		if complete {
			if !sink.discardLine && len(bytes.TrimSpace(sink.buffer)) > 0 {
				sink.publishLine(bytes.TrimSuffix(sink.buffer, []byte{'\r'}))
			}
			sink.buffer = sink.buffer[:0]
			sink.discardLine = false
		}
	}
	return len(input), nil
}

func (sink *JSONLineSink) publishLine(line []byte) {
	sanitized, err := redactJSON(line, sink.secrets)
	if err != nil {
		sink.report(fmt.Errorf("sanitize stream record: %w", err))
		return
	}
	var header recordHeader
	if err := json.Unmarshal(sanitized, &header); err != nil {
		sink.report(fmt.Errorf("decode stream record header: %w", err))
		return
	}
	monotonic, err := strconv.ParseUint(header.ServerReceivedMonotonicNS, 10, 64)
	if err != nil || monotonic == 0 {
		sink.report(errors.New("stream record is missing server monotonic time"))
		return
	}
	unix, err := strconv.ParseUint(header.ServerReceivedUnixNS, 10, 64)
	if err != nil || unix == 0 {
		sink.report(errors.New("stream record is missing server Unix time"))
		return
	}

	kernelFact := header.RecordType == "" && header.EventTypeName != "drop_notice" && header.EventTypeName != "self_diag"
	eventType := header.EventTypeName
	recordType := "kernel_event"
	source := "kernel_fact"
	if header.RecordType != "" {
		eventType = header.RecordType
		recordType = header.RecordType
		source = "policy_decision"
		switch header.RecordType {
		case "agent_checkpoint":
			source = "agent_claim"
		case "containment_result":
			source = "containment_result"
		case "derived_record_error", "drop_notice", "self_diag":
			source = "diagnostic"
		}
	} else if !kernelFact {
		source = "diagnostic"
	}
	if eventType == "" {
		eventType = recordType
	}
	var droppedCount uint64
	if eventType == "drop_notice" {
		droppedCount, err = strconv.ParseUint(header.DroppedCount, 10, 64)
		if err != nil || droppedCount == 0 || header.DroppedEventTypeName == "" {
			sink.report(errors.New("drop notice is missing a valid per-type count"))
			return
		}
	}
	severity := "info"
	if header.ActionResultName == "blocked" {
		severity = "high"
	} else if header.ActionName == "alert" || header.ActionName == "contain" || strings.Contains(eventType, "error") || strings.Contains(eventType, "drop") {
		severity = "medium"
	}
	digest := sha256.Sum256(sanitized)
	identifier := recordType + "-" + hex.EncodeToString(digest[:12])
	_, err = sink.hub.Publish(Event{
		ID: identifier, Type: recordType, Source: source, RunID: sink.options.RunID,
		Severity: severity, EventType: eventType, ServerMonotonicNS: monotonic,
		ServerUnixNS: unix, Audit: kernelFact && header.ActionName == "audit", Payload: sanitized,
	})
	if err != nil {
		sink.report(fmt.Errorf("publish stream record: %w", err))
		return
	}
	if sink.options.OnPublished != nil {
		sink.options.OnPublished(PublishedRecord{
			RunID: sink.options.RunID, KernelFact: kernelFact,
			PolicyDecision: header.RecordType == "policy_decision", Blocked: header.ActionResultName == "blocked",
			DroppedType: header.DroppedEventTypeName, DroppedCount: droppedCount,
		})
	}
}

func (sink *JSONLineSink) report(err error) {
	if sink.options.OnError != nil {
		sink.options.OnError(err)
	}
}

func redactJSON(input []byte, secrets []string) (json.RawMessage, error) {
	decoder := json.NewDecoder(bytes.NewReader(input))
	decoder.UseNumber()
	var value any
	if err := decoder.Decode(&value); err != nil {
		return nil, err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return nil, errors.New("stream JSON has trailing content")
	}
	redacted, err := redactValue(value, secrets, 0)
	if err != nil {
		return nil, err
	}
	encoded, err := json.Marshal(redacted)
	if err != nil || len(encoded) > maxPayloadBytes {
		return nil, errors.New("sanitized stream payload exceeds limit")
	}
	return encoded, nil
}

func redactValue(value any, secrets []string, depth int) (any, error) {
	if depth > 32 {
		return nil, errors.New("stream JSON nesting exceeds limit")
	}
	switch typed := value.(type) {
	case map[string]any:
		argumentsTruncated, _ := typed["arguments_truncated"].(bool)
		for key, child := range typed {
			if sensitiveKey(key) {
				typed[key] = "[REDACTED]"
				continue
			}
			if normalizedKey(key) == "argv" {
				if argumentsTruncated {
					typed[key] = []any{"[REDACTED]"}
					continue
				}
				if arguments, ok := child.([]any); ok {
					typed[key] = redactArguments(arguments, secrets)
					continue
				}
			}
			redacted, err := redactValue(child, secrets, depth+1)
			if err != nil {
				return nil, err
			}
			typed[key] = redacted
		}
		return typed, nil
	case []any:
		for index, child := range typed {
			redacted, err := redactValue(child, secrets, depth+1)
			if err != nil {
				return nil, err
			}
			typed[index] = redacted
		}
		return typed, nil
	case string:
		return redactText(typed, secrets), nil
	default:
		return value, nil
	}
}

func sensitiveKey(key string) bool {
	normalized := normalizedKey(key)
	for _, suffix := range []string{"prompt", "token", "authorization", "password", "passwd", "secret", "apikey", "accesskey", "clientsecret", "cookie", "privatekey", "credential", "credentials"} {
		if strings.HasSuffix(normalized, suffix) {
			return true
		}
	}
	return false
}

func normalizedKey(key string) string {
	key = strings.ToLower(strings.TrimLeft(key, "-"))
	return strings.NewReplacer("-", "", "_", "", ".", "").Replace(key)
}

func redactArguments(arguments []any, secrets []string) []any {
	redacted := make([]any, len(arguments))
	redactNext := false
	for index, argument := range arguments {
		text, ok := argument.(string)
		if !ok {
			redacted[index] = argument
			redactNext = false
			continue
		}
		if redactNext {
			redacted[index] = "[REDACTED]"
			redactNext = false
			continue
		}
		redacted[index] = redactText(text, secrets)
		if sensitiveKey(text) && !strings.Contains(text, "=") {
			redactNext = true
		}
	}
	return redacted
}

func redactText(value string, secrets []string) string {
	value = textCredentialPattern.ReplaceAllString(value, "[REDACTED]")
	for _, secret := range secrets {
		value = strings.ReplaceAll(value, secret, "[REDACTED]")
	}
	return value
}
