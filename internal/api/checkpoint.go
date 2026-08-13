package api

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const (
	CheckpointPathPattern       = "POST /ingest/v1/runs/{run_id}/checkpoints"
	defaultCheckpointBodyBytes  = 64 << 10
	defaultCheckpointRate       = 20
	defaultCheckpointCapacity   = 1024
	defaultCheckpointRunBytes   = 4 << 20
	defaultCheckpointTotalBytes = 64 << 20
	maxCheckpointStringBytes    = 1024
	maxCheckpointSummaryBytes   = 4096
	maxCheckpointMapEntries     = 32
)

var (
	errCheckpointConflict = errors.New("checkpoint sequence or idempotency conflict")
	errCheckpointRate     = errors.New("checkpoint rate limit exceeded")
	errCheckpointAuth     = errors.New("checkpoint authorization failed")
	errCheckpointService  = errors.New("checkpoint ingest temporarily unavailable")
	idempotencyPattern    = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)
)

type CheckpointReceiptTime struct {
	MonotonicNS uint64
	UnixNS      uint64
	ErrorNS     uint64
}

type CheckpointClock func() (CheckpointReceiptTime, error)

type CheckpointRequest struct {
	Sequence             string            `json:"sequence,omitempty"`
	IdempotencyKey       string            `json:"idempotency_key,omitempty"`
	Type                 string            `json:"type"`
	Phase                string            `json:"phase,omitempty"`
	ToolName             string            `json:"tool_name,omitempty"`
	Summary              string            `json:"summary,omitempty"`
	Labels               map[string]string `json:"labels,omitempty"`
	Metadata             map[string]string `json:"metadata,omitempty"`
	ClientReportedUnixNS string            `json:"client_reported_unix_ns,omitempty"`
}

type Checkpoint struct {
	CheckpointID              string            `json:"checkpoint_id"`
	RunID                     string            `json:"run_id"`
	Sequence                  string            `json:"sequence"`
	IdempotencyKey            string            `json:"idempotency_key,omitempty"`
	ServerReceivedMonotonicNS string            `json:"server_received_monotonic_ns"`
	ServerReceivedUnixNS      string            `json:"server_received_unix_ns"`
	ClockCalibrationErrorNS   string            `json:"clock_calibration_error_ns"`
	ClientReportedUnixNS      string            `json:"client_reported_unix_ns,omitempty"`
	Type                      string            `json:"type"`
	Phase                     string            `json:"phase,omitempty"`
	ToolName                  string            `json:"tool_name,omitempty"`
	Summary                   string            `json:"summary,omitempty"`
	Labels                    map[string]string `json:"labels,omitempty"`
	Metadata                  map[string]string `json:"metadata,omitempty"`
	Source                    string            `json:"source"`
}

type checkpointEnvelope struct {
	record        Checkpoint
	fingerprint   [sha256.Size]byte
	retainedBytes int64
}

type checkpointRunState struct {
	nextSequence  uint64
	bySequence    map[uint64]checkpointEnvelope
	byKey         map[string]checkpointEnvelope
	rateTokens    float64
	rateUpdated   int64
	retainedBytes int64
}

type CheckpointOptions struct {
	Clock               CheckpointClock
	Random              io.Reader
	MaxBodyBytes        int64
	RequestsPerSecond   int
	CapacityPerRun      int
	CapacityBytesPerRun int64
	CapacityBytesTotal  int64
}

// CheckpointHandler is an isolated ingest surface. It intentionally exposes no
// management routes and serializes authorization, replay state, and insertion
// with the Run lifecycle lock.
type CheckpointHandler struct {
	registration        *RegistrationHandler
	clock               CheckpointClock
	random              io.Reader
	maxBodyBytes        int64
	requestsPerSecond   int
	capacityPerRun      int
	capacityBytesPerRun int64
	capacityBytesTotal  int64
}

func NewCheckpointHandler(registration *RegistrationHandler, options CheckpointOptions) (*CheckpointHandler, error) {
	if registration == nil || registration.store == nil {
		return nil, errors.New("registration handler is required")
	}
	if options.Clock == nil {
		options.Clock = captureCheckpointReceiptTime
	}
	if options.Random == nil {
		options.Random = registration.random
	}
	if options.MaxBodyBytes == 0 {
		options.MaxBodyBytes = defaultCheckpointBodyBytes
	}
	if options.RequestsPerSecond == 0 {
		options.RequestsPerSecond = defaultCheckpointRate
	}
	if options.CapacityPerRun == 0 {
		options.CapacityPerRun = defaultCheckpointCapacity
	}
	if options.CapacityBytesPerRun == 0 {
		options.CapacityBytesPerRun = defaultCheckpointRunBytes
	}
	if options.CapacityBytesTotal == 0 {
		options.CapacityBytesTotal = defaultCheckpointTotalBytes
	}
	if options.MaxBodyBytes < 1 || options.MaxBodyBytes > defaultCheckpointBodyBytes {
		return nil, fmt.Errorf("checkpoint body limit must be between 1 and %d bytes", defaultCheckpointBodyBytes)
	}
	if options.RequestsPerSecond < 1 || options.RequestsPerSecond > defaultCheckpointRate {
		return nil, fmt.Errorf("checkpoint rate must be between 1 and %d requests per second", defaultCheckpointRate)
	}
	if options.CapacityPerRun < 1 || options.CapacityPerRun > defaultCheckpointCapacity {
		return nil, fmt.Errorf("checkpoint capacity must be between 1 and %d per Run", defaultCheckpointCapacity)
	}
	if options.CapacityBytesPerRun < 1 || options.CapacityBytesPerRun > defaultCheckpointRunBytes {
		return nil, fmt.Errorf("checkpoint byte capacity must be between 1 and %d per Run", defaultCheckpointRunBytes)
	}
	if options.CapacityBytesTotal < options.CapacityBytesPerRun || options.CapacityBytesTotal > defaultCheckpointTotalBytes {
		return nil, fmt.Errorf("checkpoint total byte capacity must be between per-Run capacity and %d", defaultCheckpointTotalBytes)
	}
	return &CheckpointHandler{
		registration: registration, clock: options.Clock, random: options.Random,
		maxBodyBytes: options.MaxBodyBytes, requestsPerSecond: options.RequestsPerSecond,
		capacityPerRun: options.CapacityPerRun, capacityBytesPerRun: options.CapacityBytesPerRun,
		capacityBytesTotal: options.CapacityBytesTotal,
	}, nil
}

func (handler *CheckpointHandler) Routes() http.Handler {
	mux := http.NewServeMux()
	mux.Handle(CheckpointPathPattern, handler)
	return mux
}

func (handler *CheckpointHandler) ServeHTTP(response http.ResponseWriter, request *http.Request) {
	if handler == nil || handler.registration == nil {
		http.Error(response, "checkpoint ingest unavailable", http.StatusServiceUnavailable)
		return
	}
	token, ok := bearerToken(request.Header.Get("Authorization"))
	if !ok {
		unauthorized(response)
		return
	}
	runID := request.PathValue("run_id")
	if err := handler.authorizeAndCharge(request.Context(), runID, token); err != nil {
		switch {
		case errors.Is(err, errCheckpointRate):
			response.Header().Set("Retry-After", "1")
			http.Error(response, http.StatusText(http.StatusTooManyRequests), http.StatusTooManyRequests)
		case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
			http.Error(response, "request canceled", http.StatusRequestTimeout)
		default:
			unauthorized(response)
		}
		return
	}
	if mediaType := strings.ToLower(strings.TrimSpace(strings.Split(request.Header.Get("Content-Type"), ";")[0])); mediaType != "application/json" {
		http.Error(response, "content type must be application/json", http.StatusUnsupportedMediaType)
		return
	}
	payload, err := readCheckpointBody(response, request, handler.maxBodyBytes)
	if err != nil {
		if errors.Is(err, errCheckpointBodyTooLarge) {
			http.Error(response, "checkpoint request is too large", http.StatusRequestEntityTooLarge)
			return
		}
		http.Error(response, "invalid checkpoint request", http.StatusBadRequest)
		return
	}
	if err := rejectDuplicateJSONNames(payload); err != nil {
		http.Error(response, "invalid checkpoint request", http.StatusBadRequest)
		return
	}
	var input CheckpointRequest
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&input); err != nil || ensureJSONEOF(decoder) != nil {
		http.Error(response, "invalid checkpoint request", http.StatusBadRequest)
		return
	}
	input.Type = strings.TrimSpace(input.Type)
	sequence, clientTime, err := validateCheckpointRequest(input)
	if err != nil {
		http.Error(response, err.Error(), http.StatusBadRequest)
		return
	}
	fingerprint, err := checkpointFingerprint(input, sequence, clientTime)
	if err != nil {
		http.Error(response, "invalid checkpoint request", http.StatusBadRequest)
		return
	}

	record, replayed, err := handler.accept(
		request.Context(), runID, token, input, sequence, clientTime,
		fingerprint, int64(len(payload))+4096,
	)
	if err != nil {
		switch {
		case errors.Is(err, errCheckpointConflict):
			http.Error(response, http.StatusText(http.StatusConflict), http.StatusConflict)
		case errors.Is(err, errCheckpointRate):
			response.Header().Set("Retry-After", "1")
			http.Error(response, http.StatusText(http.StatusTooManyRequests), http.StatusTooManyRequests)
		case errors.Is(err, errCheckpointAuth):
			unauthorized(response)
		case errors.Is(err, errCheckpointService):
			response.Header().Set("Retry-After", "1")
			http.Error(response, http.StatusText(http.StatusServiceUnavailable), http.StatusServiceUnavailable)
		case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
			http.Error(response, "request canceled", http.StatusRequestTimeout)
		default:
			http.Error(response, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		}
		return
	}
	response.Header().Set("Content-Type", "application/json")
	response.Header().Set("Cache-Control", "no-store")
	status := http.StatusCreated
	if replayed {
		status = http.StatusOK
		response.Header().Set("Idempotency-Replayed", "true")
	}
	_ = writeJSON(response, status, record)
}

func (handler *CheckpointHandler) authorizeAndCharge(ctx context.Context, runID, token string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	parsedRunID, tokenHash, tokenExpiry, err := handler.registration.parseIngestToken(token)
	if err != nil || parsedRunID != runID {
		return errCheckpointAuth
	}
	store := handler.registration.store
	store.mu.Lock()
	defer store.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	now := handler.registration.now().UTC()
	if !checkpointRunAuthorizedLocked(store, runID, tokenHash, tokenExpiry, now) {
		return errCheckpointAuth
	}
	if store.checkpoints == nil {
		store.checkpoints = make(map[string]*checkpointRunState)
	}
	state := store.checkpoints[runID]
	if state == nil {
		state = &checkpointRunState{
			nextSequence: 1,
			bySequence:   make(map[uint64]checkpointEnvelope),
			byKey:        make(map[string]checkpointEnvelope),
			rateTokens:   float64(handler.requestsPerSecond),
			rateUpdated:  now.UnixNano(),
		}
		store.checkpoints[runID] = state
	}
	refillCheckpointTokens(state, now.UnixNano(), handler.requestsPerSecond)
	if state.rateTokens < 1 {
		return errCheckpointRate
	}
	state.rateTokens--
	return nil
}

func checkpointRunAuthorizedLocked(store *RunStore, runID string, tokenHash []byte, tokenExpiry, now time.Time) bool {
	if !now.Before(tokenExpiry) {
		return false
	}
	run, exists := store.runs[runID]
	if !exists || !hmac.Equal(run.TokenHash[:], tokenHash) || run.Status != "active" ||
		run.RunExpiry.IsZero() || !now.Before(run.RunExpiry) || !now.Before(run.TokenExpiry) {
		return false
	}
	_, terminating := store.terminating[runID]
	return !terminating
}

func (handler *CheckpointHandler) accept(ctx context.Context, runID, token string, input CheckpointRequest, requestedSequence, clientTime uint64, fingerprint [sha256.Size]byte, retainedBytes int64) (Checkpoint, bool, error) {
	if err := ctx.Err(); err != nil {
		return Checkpoint{}, false, err
	}
	parsedRunID, tokenHash, tokenExpiry, err := handler.registration.parseIngestToken(token)
	if err != nil || parsedRunID != runID {
		return Checkpoint{}, false, errCheckpointAuth
	}

	store := handler.registration.store
	store.mu.Lock()
	defer store.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return Checkpoint{}, false, err
	}
	now := handler.registration.now().UTC()
	if !checkpointRunAuthorizedLocked(store, runID, tokenHash, tokenExpiry, now) {
		return Checkpoint{}, false, errCheckpointAuth
	}
	run := store.runs[runID]
	state := store.checkpoints[runID]
	if state == nil {
		return Checkpoint{}, false, errCheckpointService
	}
	if replay, ok, conflict := checkpointReplay(state, requestedSequence, input.IdempotencyKey, fingerprint); ok {
		return replay, true, nil
	} else if conflict {
		return Checkpoint{}, false, errCheckpointConflict
	}
	sequence := requestedSequence
	if sequence == 0 {
		sequence = state.nextSequence
	}
	if sequence != state.nextSequence {
		return Checkpoint{}, false, errCheckpointConflict
	}
	if len(state.bySequence) >= handler.capacityPerRun {
		return Checkpoint{}, false, errCheckpointService
	}
	if retainedBytes < 1 || state.retainedBytes+retainedBytes > handler.capacityBytesPerRun ||
		store.checkpointBytes+retainedBytes > handler.capacityBytesTotal {
		return Checkpoint{}, false, errCheckpointService
	}
	receipt, err := handler.clock()
	if err != nil || receipt.MonotonicNS == 0 || receipt.UnixNS == 0 {
		return Checkpoint{}, false, errCheckpointService
	}
	checkpointID, err := randomHex(handler.random, 16)
	if err != nil {
		return Checkpoint{}, false, errCheckpointService
	}
	record := Checkpoint{
		CheckpointID: checkpointID, RunID: run.RunID, Sequence: strconv.FormatUint(sequence, 10),
		IdempotencyKey:            input.IdempotencyKey,
		ServerReceivedMonotonicNS: strconv.FormatUint(receipt.MonotonicNS, 10),
		ServerReceivedUnixNS:      strconv.FormatUint(receipt.UnixNS, 10),
		ClockCalibrationErrorNS:   strconv.FormatUint(receipt.ErrorNS, 10),
		Type:                      input.Type, Phase: input.Phase, ToolName: input.ToolName, Summary: input.Summary,
		Labels: cloneLabels(input.Labels), Metadata: cloneLabels(input.Metadata), Source: "agent_claim",
	}
	if clientTime != 0 {
		record.ClientReportedUnixNS = strconv.FormatUint(clientTime, 10)
	}
	envelope := checkpointEnvelope{record: record, fingerprint: fingerprint, retainedBytes: retainedBytes}
	state.bySequence[sequence] = envelope
	if input.IdempotencyKey != "" {
		state.byKey[input.IdempotencyKey] = envelope
	}
	state.nextSequence++
	state.retainedBytes += retainedBytes
	store.checkpointBytes += retainedBytes
	return cloneCheckpoint(record), false, nil
}

func (store *RunStore) dropCheckpointStateLocked(runID string) {
	state := store.checkpoints[runID]
	if state == nil {
		return
	}
	store.checkpointBytes -= state.retainedBytes
	if store.checkpointBytes < 0 {
		store.checkpointBytes = 0
	}
	delete(store.checkpoints, runID)
}

func refillCheckpointTokens(state *checkpointRunState, nowNS int64, limit int) {
	maximum := float64(limit)
	if state.rateTokens > maximum {
		state.rateTokens = maximum
	}
	if nowNS <= state.rateUpdated {
		return
	}
	elapsedSeconds := float64(nowNS-state.rateUpdated) / float64(1_000_000_000)
	state.rateTokens += elapsedSeconds * float64(limit)
	if state.rateTokens > maximum {
		state.rateTokens = maximum
	}
	state.rateUpdated = nowNS
}

func checkpointReplay(state *checkpointRunState, sequence uint64, key string, fingerprint [sha256.Size]byte) (Checkpoint, bool, bool) {
	var found *checkpointEnvelope
	if sequence != 0 {
		if envelope, exists := state.bySequence[sequence]; exists {
			copy := envelope
			found = &copy
		}
	}
	if key != "" {
		if envelope, exists := state.byKey[key]; exists {
			if found != nil && found.record.CheckpointID != envelope.record.CheckpointID {
				return Checkpoint{}, false, true
			}
			copy := envelope
			found = &copy
		}
	}
	if found == nil {
		return Checkpoint{}, false, false
	}
	if !hmac.Equal(found.fingerprint[:], fingerprint[:]) {
		return Checkpoint{}, false, true
	}
	return cloneCheckpoint(found.record), true, false
}

var errCheckpointBodyTooLarge = errors.New("checkpoint body too large")

func readCheckpointBody(response http.ResponseWriter, request *http.Request, limit int64) ([]byte, error) {
	reader := http.MaxBytesReader(response, request.Body, limit)
	payload, err := io.ReadAll(reader)
	if err != nil {
		var maxBytesError *http.MaxBytesError
		if errors.As(err, &maxBytesError) {
			return nil, errCheckpointBodyTooLarge
		}
		return nil, err
	}
	if len(bytes.TrimSpace(payload)) == 0 {
		return nil, errors.New("empty checkpoint request")
	}
	return payload, nil
}

func rejectDuplicateJSONNames(payload []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(payload))
	var readValue func() error
	readValue = func() error {
		token, err := decoder.Token()
		if err != nil {
			return err
		}
		delimiter, structured := token.(json.Delim)
		if !structured {
			return nil
		}
		switch delimiter {
		case '{':
			seen := make(map[string]struct{})
			for decoder.More() {
				nameToken, err := decoder.Token()
				if err != nil {
					return err
				}
				name, ok := nameToken.(string)
				if !ok {
					return errors.New("JSON object name is not a string")
				}
				if _, duplicate := seen[name]; duplicate {
					return errors.New("duplicate JSON object name")
				}
				seen[name] = struct{}{}
				if err := readValue(); err != nil {
					return err
				}
			}
		case '[':
			for decoder.More() {
				if err := readValue(); err != nil {
					return err
				}
			}
		default:
			return errors.New("invalid JSON delimiter")
		}
		_, err = decoder.Token()
		return err
	}
	return readValue()
}

func bearerToken(header string) (string, bool) {
	scheme, token, ok := strings.Cut(strings.TrimSpace(header), " ")
	if !ok || !strings.EqualFold(scheme, "Bearer") || token == "" || strings.ContainsAny(token, " \t\r\n") {
		return "", false
	}
	return token, true
}

func unauthorized(response http.ResponseWriter) {
	response.Header().Set("WWW-Authenticate", "Bearer")
	http.Error(response, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
}

func validateCheckpointRequest(input CheckpointRequest) (uint64, uint64, error) {
	sequence, err := parseOptionalPositiveUint64(input.Sequence, "sequence")
	if err != nil {
		return 0, 0, err
	}
	if sequence == 0 && input.IdempotencyKey == "" {
		return 0, 0, errors.New("sequence or idempotency_key is required")
	}
	if input.IdempotencyKey != "" && !idempotencyPattern.MatchString(input.IdempotencyKey) {
		return 0, 0, errors.New("idempotency_key is invalid")
	}
	if !validCheckpointType(input.Type) {
		return 0, 0, errors.New("checkpoint type is unsupported")
	}
	for name, value := range map[string]string{
		"phase": input.Phase, "tool_name": input.ToolName,
	} {
		if len(value) > maxCheckpointStringBytes {
			return 0, 0, fmt.Errorf("%s exceeds %d bytes", name, maxCheckpointStringBytes)
		}
	}
	if len(input.Summary) > maxCheckpointSummaryBytes {
		return 0, 0, fmt.Errorf("summary exceeds %d bytes", maxCheckpointSummaryBytes)
	}
	if err := validateCheckpointMap("labels", input.Labels); err != nil {
		return 0, 0, err
	}
	if err := validateCheckpointMap("metadata", input.Metadata); err != nil {
		return 0, 0, err
	}
	clientTime, err := parseOptionalPositiveUint64(input.ClientReportedUnixNS, "client_reported_unix_ns")
	if err != nil {
		return 0, 0, err
	}
	return sequence, clientTime, nil
}

func validCheckpointType(value string) bool {
	switch value {
	case "run_started", "llm_request", "llm_response", "tool_planned", "tool_started", "tool_finished", "run_finished", "run_failed":
		return true
	default:
		return false
	}
}

func validateCheckpointMap(name string, values map[string]string) error {
	if len(values) > maxCheckpointMapEntries {
		return fmt.Errorf("%s exceeds %d entries", name, maxCheckpointMapEntries)
	}
	for key, value := range values {
		if strings.TrimSpace(key) == "" || len(key) > 128 || len(value) > maxCheckpointStringBytes {
			return fmt.Errorf("%s contains an invalid key or value", name)
		}
	}
	return nil
}

func parseOptionalPositiveUint64(value, name string) (uint64, error) {
	if value == "" {
		return 0, nil
	}
	parsed, err := strconv.ParseUint(value, 10, 64)
	if err != nil || parsed == 0 {
		return 0, fmt.Errorf("%s must be a positive decimal string", name)
	}
	return parsed, nil
}

func checkpointFingerprint(input CheckpointRequest, sequence, clientTime uint64) ([sha256.Size]byte, error) {
	canonical := struct {
		Sequence       uint64            `json:"sequence"`
		IdempotencyKey string            `json:"idempotency_key"`
		Type           string            `json:"type"`
		Phase          string            `json:"phase"`
		ToolName       string            `json:"tool_name"`
		Summary        string            `json:"summary"`
		Labels         map[string]string `json:"labels"`
		Metadata       map[string]string `json:"metadata"`
		ClientTime     uint64            `json:"client_time"`
	}{sequence, input.IdempotencyKey, input.Type, input.Phase, input.ToolName, input.Summary, input.Labels, input.Metadata, clientTime}
	encoded, err := json.Marshal(canonical)
	if err != nil {
		return [sha256.Size]byte{}, err
	}
	return sha256.Sum256(encoded), nil
}

func cloneCheckpoint(record Checkpoint) Checkpoint {
	record.Labels = cloneLabels(record.Labels)
	record.Metadata = cloneLabels(record.Metadata)
	return record
}
