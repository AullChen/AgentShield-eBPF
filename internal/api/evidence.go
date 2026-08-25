package api

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/agentshield/agentshield-ebpf/internal/evidence"
	"github.com/agentshield/agentshield-ebpf/internal/stream"
)

const evidenceSnapshotLimit = 10_000

type EvidenceProvider interface {
	Evidence(context.Context, string) (evidence.Timeline, error)
}

// StreamEvidenceProvider projects the bounded WebSocket recovery window into
// the evidence schema. It deliberately does not synthesize Agent checkpoints,
// correlation, or exact attribution that the standalone audit process does not
// possess.
type StreamEvidenceProvider struct {
	hub *stream.Hub
}

func NewStreamEvidenceProvider(hub *stream.Hub) (*StreamEvidenceProvider, error) {
	if hub == nil {
		return nil, errors.New("evidence stream hub is required")
	}
	return &StreamEvidenceProvider{hub: hub}, nil
}

func (provider *StreamEvidenceProvider) Evidence(_ context.Context, runID string) (evidence.Timeline, error) {
	if runID == "" || len(runID) > 128 {
		return evidence.Timeline{}, errors.New("evidence Run ID is invalid")
	}
	messages, err := provider.hub.Snapshot(stream.Filter{RunID: runID, IncludeAudit: true}, evidenceSnapshotLimit)
	if err != nil {
		return evidence.Timeline{}, err
	}
	events := make([]evidence.Event, 0, len(messages))
	for _, message := range messages {
		event, include, err := evidenceEvent(message)
		if err != nil {
			return evidence.Timeline{}, err
		}
		if include {
			events = append(events, event)
		}
	}
	return evidence.Build(runID, events)
}

func evidenceEvent(message stream.Message) (evidence.Event, bool, error) {
	monotonic, err := strconv.ParseUint(message.ServerMonotonicNS, 10, 64)
	if err != nil || monotonic == 0 {
		return evidence.Event{}, false, errors.New("stream evidence has invalid monotonic time")
	}
	unix, err := strconv.ParseUint(message.ServerUnixNS, 10, 64)
	if err != nil || unix == 0 {
		return evidence.Event{}, false, errors.New("stream evidence has invalid Unix time")
	}
	var payload map[string]any
	if err := json.Unmarshal(message.Payload, &payload); err != nil {
		return evidence.Event{}, false, fmt.Errorf("decode stream evidence payload: %w", err)
	}
	event := evidence.Event{
		ID: message.ID, Type: message.EventType, ServerMonotonicNS: monotonic,
		ServerUnixNS: unix, Summary: evidenceSummary(message, payload),
	}
	switch message.Source {
	case string(evidence.AgentClaim):
		event.Source = evidence.AgentClaim
	case string(evidence.KernelFact):
		event.Source = evidence.KernelFact
		event.Operation = &evidence.OperationResult{
			AttemptObserved: true, ActionResult: stringField(payload, "action_result_name", "unknown"),
			Mechanism: kernelMechanism(message.EventType, payload),
		}
	case string(evidence.PolicyDecision):
		final, _ := payload["final"].(map[string]any)
		if final == nil {
			return evidence.Event{}, false, nil
		}
		event.Source = evidence.PolicyDecision
		event.Decision = &evidence.Decision{
			PolicyID: stringField(final, "policy_id", "unknown"), RuleID: decimalField(final, "rule_id"),
			RequestedAction: stringField(final, "requested_action", "unknown"),
			FinalDecision:   stringField(final, "policy_decision", "unknown"),
			Enforced:        boolField(final, "enforced"), Mechanism: decisionMechanism(final, stringField(payload, "event_type_name", message.EventType)),
		}
	case string(evidence.ContainmentResult):
		event.Source = evidence.ContainmentResult
		event.Containment = &evidence.Containment{
			Requested: boolField(payload, "requested"), Result: stringField(payload, "result", "unknown"),
			Method: stringField(payload, "method", "unknown"), TargetIdentity: stringField(payload, "target_identity", "unknown"),
			OriginalActionResult: stringField(payload, "original_action_result", "unknown"),
		}
	default:
		return evidence.Event{}, false, nil
	}
	return event, true, nil
}

func evidenceSummary(message stream.Message, payload map[string]any) string {
	if summary, ok := payload["summary"].(string); ok && summary != "" {
		return boundedSummary(summary)
	}
	subject := stringField(payload, "data", "")
	if subject == "" {
		if destination, ok := payload["dst_ip"].(string); ok && destination != "" {
			subject = destination + ":" + decimalField(payload, "dst_port")
		}
	}
	if subject != "" {
		return boundedSummary(message.EventType + " observed: " + subject)
	}
	return message.EventType + " record observed"
}

func boundedSummary(summary string) string {
	if len(summary) <= 4096 {
		return summary
	}
	end := 0
	for index := range summary {
		if index > 4093 {
			break
		}
		end = index
	}
	return summary[:end] + "..."
}

func kernelMechanism(eventType string, payload map[string]any) string {
	switch eventType {
	case "exec_attempt":
		return "tracepoint/sys_enter_execve"
	case "file_open":
		return "tracepoint/sys_enter_openat"
	case "net_connect":
		if stringField(payload, "family_name", "ipv4") == "ipv6" {
			return "cgroup/connect6"
		}
		return "cgroup/connect4"
	default:
		return "kernel_hook"
	}
}

func decisionMechanism(final map[string]any, eventType string) string {
	if boolField(final, "enforced") && eventType == "net_connect" {
		return "cgroup/connect hook"
	}
	return "post_event evaluation"
}

func stringField(values map[string]any, key, fallback string) string {
	if value, ok := values[key].(string); ok && value != "" {
		return value
	}
	return fallback
}

func decimalField(values map[string]any, key string) string {
	switch value := values[key].(type) {
	case string:
		return value
	case float64:
		return strconv.FormatUint(uint64(value), 10)
	default:
		return "0"
	}
}

func boolField(values map[string]any, key string) bool {
	value, _ := values[key].(bool)
	return value
}

type EvidenceHandlerOptions struct {
	ReadToken string
}

type EvidenceHandler struct {
	provider  EvidenceProvider
	tokenHash [sha256.Size]byte
}

func NewEvidenceHandler(provider EvidenceProvider, options EvidenceHandlerOptions) (*EvidenceHandler, error) {
	if provider == nil || len(options.ReadToken) < 24 || len(options.ReadToken) > 512 {
		return nil, errors.New("evidence requires a provider and a 24-512 byte read token")
	}
	return &EvidenceHandler{provider: provider, tokenHash: sha256.Sum256([]byte(options.ReadToken))}, nil
}

func (handler *EvidenceHandler) Routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/v1/evidence/{run_id}", handler.ServeHTTP)
	return mux
}

func (handler *EvidenceHandler) ServeHTTP(response http.ResponseWriter, request *http.Request) {
	if !handler.authorized(request.Header.Get("Authorization")) {
		response.Header().Set("WWW-Authenticate", "Bearer")
		http.Error(response, "unauthorized", http.StatusUnauthorized)
		return
	}
	runID := request.PathValue("run_id")
	if runID == "" || len(runID) > 128 {
		http.Error(response, "invalid Run ID", http.StatusBadRequest)
		return
	}
	timeline, err := handler.provider.Evidence(request.Context(), runID)
	if err != nil {
		http.Error(response, "evidence unavailable", http.StatusServiceUnavailable)
		return
	}
	response.Header().Set("Cache-Control", "no-store")
	response.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(response).Encode(timeline)
}

func (handler *EvidenceHandler) authorized(header string) bool {
	scheme, token, ok := strings.Cut(header, " ")
	if !ok || !strings.EqualFold(scheme, "Bearer") || token == "" || len(token) > 512 || strings.ContainsAny(token, " \t\r\n") {
		return false
	}
	digest := sha256.Sum256([]byte(token))
	return subtle.ConstantTimeCompare(digest[:], handler.tokenHash[:]) == 1
}
