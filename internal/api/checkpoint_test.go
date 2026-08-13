package api

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/agentshield/agentshield-ebpf/internal/scope"
)

func TestCheckpointIngestBindsTokenAndUsesServerIdentity(t *testing.T) {
	handler, registration, registered, scopeMap := newCheckpointTestHandler(t, CheckpointOptions{})
	response := postCheckpoint(t, handler.Routes(), registered.RunID, registered.IngestToken, CheckpointRequest{
		Sequence: "1", IdempotencyKey: "checkpoint-1", Type: "tool_started",
		ToolName: "python", Summary: "sanitized summary", ClientReportedUnixNS: "999",
	})
	if response.Code != http.StatusCreated {
		t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
	}
	record := decodeCheckpoint(t, response)
	if record.RunID != registered.RunID || record.Sequence != "1" || record.Source != "agent_claim" ||
		record.ServerReceivedMonotonicNS != "100" || record.ServerReceivedUnixNS != "200" ||
		record.ClockCalibrationErrorNS != "3" || record.ClientReportedUnixNS != "999" {
		t.Fatalf("checkpoint = %+v", record)
	}
	if response.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("Cache-Control = %q", response.Header().Get("Cache-Control"))
	}

	other := addCheckpointTestRun(t, registration, "other-run", 43, 3003)
	crossRun := postCheckpoint(t, handler.Routes(), other.RunID, registered.IngestToken, CheckpointRequest{
		Sequence: "1", Type: "run_started",
	})
	if crossRun.Code != http.StatusUnauthorized {
		t.Fatalf("cross-Run status = %d", crossRun.Code)
	}
	if _, exists := scopeMap.values[42]; !exists {
		t.Fatal("checkpoint changed the scope map")
	}
}

func TestCheckpointReplayIsStableAndConflictsAreRejected(t *testing.T) {
	handler, _, registered, _ := newCheckpointTestHandler(t, CheckpointOptions{})
	input := CheckpointRequest{Sequence: "1", IdempotencyKey: "same-key", Type: "tool_finished", Summary: "done"}
	first := postCheckpoint(t, handler.Routes(), registered.RunID, registered.IngestToken, input)
	replayed := postCheckpoint(t, handler.Routes(), registered.RunID, registered.IngestToken, input)
	if first.Code != http.StatusCreated || replayed.Code != http.StatusOK ||
		replayed.Header().Get("Idempotency-Replayed") != "true" {
		t.Fatalf("statuses = %d/%d replay=%q", first.Code, replayed.Code, replayed.Header().Get("Idempotency-Replayed"))
	}
	firstRecord := decodeCheckpoint(t, first)
	replayRecord := decodeCheckpoint(t, replayed)
	if !checkpointsEqual(firstRecord, replayRecord) {
		t.Fatalf("replay changed record: first=%+v replay=%+v", firstRecord, replayRecord)
	}

	input.Summary = "different"
	conflict := postCheckpoint(t, handler.Routes(), registered.RunID, registered.IngestToken, input)
	if conflict.Code != http.StatusConflict {
		t.Fatalf("payload conflict status = %d", conflict.Code)
	}
	gap := postCheckpoint(t, handler.Routes(), registered.RunID, registered.IngestToken, CheckpointRequest{
		Sequence: "3", Type: "tool_started",
	})
	if gap.Code != http.StatusConflict {
		t.Fatalf("sequence gap status = %d", gap.Code)
	}
	next := postCheckpoint(t, handler.Routes(), registered.RunID, registered.IngestToken, CheckpointRequest{
		Sequence: "2", Type: "tool_started",
	})
	if next.Code != http.StatusCreated {
		t.Fatalf("next sequence status = %d, body = %s", next.Code, next.Body.String())
	}
}

func TestCheckpointIdempotencyKeyCanAllocateSequence(t *testing.T) {
	handler, _, registered, _ := newCheckpointTestHandler(t, CheckpointOptions{})
	input := CheckpointRequest{IdempotencyKey: "allocate-sequence", Type: "run_started"}
	first := postCheckpoint(t, handler.Routes(), registered.RunID, registered.IngestToken, input)
	replayed := postCheckpoint(t, handler.Routes(), registered.RunID, registered.IngestToken, input)
	if first.Code != http.StatusCreated || replayed.Code != http.StatusOK {
		t.Fatalf("statuses = %d/%d", first.Code, replayed.Code)
	}
	if record := decodeCheckpoint(t, first); record.Sequence != "1" {
		t.Fatalf("allocated sequence = %q", record.Sequence)
	}
}

func TestCheckpointConcurrentReplayCreatesOneRecord(t *testing.T) {
	handler, _, registered, _ := newCheckpointTestHandler(t, CheckpointOptions{})
	routes := handler.Routes()
	const requests = 12
	codes := make(chan int, requests)
	ids := make(chan string, requests)
	var group sync.WaitGroup
	for range requests {
		group.Add(1)
		go func() {
			defer group.Done()
			response := postCheckpointResponse(routes, registered.RunID, registered.IngestToken, CheckpointRequest{
				Sequence: "1", IdempotencyKey: "concurrent", Type: "run_started",
			})
			codes <- response.Code
			var record Checkpoint
			_ = json.Unmarshal(response.Body.Bytes(), &record)
			ids <- record.CheckpointID
		}()
	}
	group.Wait()
	close(codes)
	close(ids)
	created := 0
	for code := range codes {
		if code == http.StatusCreated {
			created++
		} else if code != http.StatusOK {
			t.Fatalf("concurrent status = %d", code)
		}
	}
	if created != 1 {
		t.Fatalf("created responses = %d, want one", created)
	}
	uniqueIDs := make(map[string]struct{})
	for id := range ids {
		uniqueIDs[id] = struct{}{}
	}
	if len(uniqueIDs) != 1 {
		t.Fatalf("checkpoint IDs = %v", uniqueIDs)
	}
}

func TestCheckpointRunFinishedIsOnlyAnAgentClaim(t *testing.T) {
	handler, registration, registered, scopeMap := newCheckpointTestHandler(t, CheckpointOptions{})
	finishedClaim := postCheckpoint(t, handler.Routes(), registered.RunID, registered.IngestToken, CheckpointRequest{
		Sequence: "1", Type: "run_finished", Summary: "agent says it is done",
	})
	if finishedClaim.Code != http.StatusCreated {
		t.Fatalf("run_finished status = %d", finishedClaim.Code)
	}
	run, exists := registration.store.Get(registered.RunID)
	if !exists || run.Status != "active" || !run.EndedAt.IsZero() {
		t.Fatalf("run_finished claim changed Run: %+v", run)
	}
	if _, exists := scopeMap.values[42]; !exists {
		t.Fatal("run_finished claim removed scope")
	}
	next := postCheckpoint(t, handler.Routes(), registered.RunID, registered.IngestToken, CheckpointRequest{
		Sequence: "2", Type: "tool_finished",
	})
	if next.Code != http.StatusCreated {
		t.Fatalf("post-claim checkpoint status = %d", next.Code)
	}
}

func TestCheckpointIngestSurfaceExcludesManagementRoutes(t *testing.T) {
	handler, _, registered, _ := newCheckpointTestHandler(t, CheckpointOptions{})
	for _, path := range []string{RegisterPath, "/api/v1/agents/" + registered.RunID + "/finish"} {
		request := httptest.NewRequest(http.MethodPost, path, nil)
		response := httptest.NewRecorder()
		handler.Routes().ServeHTTP(response, request)
		if response.Code != http.StatusNotFound {
			t.Fatalf("ingest route %q status = %d, want 404", path, response.Code)
		}
	}
}

func TestCheckpointRejectsInvalidBodiesAndCredentials(t *testing.T) {
	handler, registration, registered, _ := newCheckpointTestHandler(t, CheckpointOptions{MaxBodyBytes: 128})
	tests := []struct {
		name        string
		contentType string
		token       string
		body        string
		status      int
	}{
		{name: "missing token", contentType: "application/json", body: `{"sequence":"1","type":"run_started"}`, status: http.StatusUnauthorized},
		{name: "wrong media", contentType: "text/plain", token: registered.IngestToken, body: `{}`, status: http.StatusUnsupportedMediaType},
		{name: "unknown field", contentType: "application/json", token: registered.IngestToken, body: `{"sequence":"1","type":"run_started","run_id":"other"}`, status: http.StatusBadRequest},
		{name: "duplicate field", contentType: "application/json", token: registered.IngestToken, body: `{"sequence":"1","type":"run_started","type":"run_finished"}`, status: http.StatusBadRequest},
		{name: "trailing", contentType: "application/json", token: registered.IngestToken, body: `{"sequence":"1","type":"run_started"}{}`, status: http.StatusBadRequest},
		{name: "oversized", contentType: "application/json", token: registered.IngestToken, body: `{"sequence":"1","type":"run_started","summary":"` + strings.Repeat("x", 128) + `"}`, status: http.StatusRequestEntityTooLarge},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodPost, "/ingest/v1/runs/"+registered.RunID+"/checkpoints", strings.NewReader(test.body))
			request.Header.Set("Content-Type", test.contentType)
			if test.token != "" {
				request.Header.Set("Authorization", "Bearer "+test.token)
			}
			response := httptest.NewRecorder()
			handler.Routes().ServeHTTP(response, request)
			if response.Code != test.status {
				t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
			}
		})
	}
	registration.now = func() time.Time { return time.Date(2026, 8, 13, 10, 1, 0, 0, time.UTC) }
	expired := postCheckpoint(t, handler.Routes(), registered.RunID, registered.IngestToken, CheckpointRequest{Sequence: "1", Type: "run_started"})
	if expired.Code != http.StatusUnauthorized {
		t.Fatalf("expired token status = %d", expired.Code)
	}
}

func TestCheckpointRateLimitAndReplayBehavior(t *testing.T) {
	handler, registration, registered, _ := newCheckpointTestHandler(t, CheckpointOptions{RequestsPerSecond: 1})
	input := CheckpointRequest{Sequence: "1", IdempotencyKey: "rate-replay", Type: "run_started"}
	if response := postCheckpoint(t, handler.Routes(), registered.RunID, registered.IngestToken, input); response.Code != http.StatusCreated {
		t.Fatalf("first status = %d", response.Code)
	}
	limitedReplay := postCheckpoint(t, handler.Routes(), registered.RunID, registered.IngestToken, input)
	if limitedReplay.Code != http.StatusTooManyRequests {
		t.Fatalf("immediate replay status = %d", limitedReplay.Code)
	}
	registration.now = func() time.Time { return time.Date(2026, 8, 13, 10, 0, 1, 0, time.UTC) }
	if response := postCheckpoint(t, handler.Routes(), registered.RunID, registered.IngestToken, input); response.Code != http.StatusOK {
		t.Fatalf("later replay status = %d", response.Code)
	}
	limited := postCheckpoint(t, handler.Routes(), registered.RunID, registered.IngestToken, CheckpointRequest{Sequence: "2", Type: "tool_started"})
	if limited.Code != http.StatusTooManyRequests || limited.Header().Get("Retry-After") != "1" {
		t.Fatalf("limited status=%d retry=%q", limited.Code, limited.Header().Get("Retry-After"))
	}
}

func TestCheckpointMalformedRequestsAreRateLimited(t *testing.T) {
	handler, registration, registered, _ := newCheckpointTestHandler(t, CheckpointOptions{RequestsPerSecond: 1})
	request := httptest.NewRequest(http.MethodPost, "/ingest/v1/runs/"+registered.RunID+"/checkpoints", strings.NewReader(`{"sequence":`))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Authorization", "Bearer "+registered.IngestToken)
	malformed := httptest.NewRecorder()
	handler.Routes().ServeHTTP(malformed, request)
	if malformed.Code != http.StatusBadRequest {
		t.Fatalf("malformed status = %d", malformed.Code)
	}
	limited := postCheckpoint(t, handler.Routes(), registered.RunID, registered.IngestToken, CheckpointRequest{
		Sequence: "1", Type: "run_started",
	})
	if limited.Code != http.StatusTooManyRequests {
		t.Fatalf("post-malformed status = %d", limited.Code)
	}
	registration.now = func() time.Time { return time.Date(2026, 8, 13, 10, 0, 1, 0, time.UTC) }
	accepted := postCheckpoint(t, handler.Routes(), registered.RunID, registered.IngestToken, CheckpointRequest{
		Sequence: "1", Type: "run_started",
	})
	if accepted.Code != http.StatusCreated {
		t.Fatalf("refilled status = %d", accepted.Code)
	}
}

func TestCheckpointRejectsExpiredRunBeforeTokenExpiry(t *testing.T) {
	handler, registration, registered, _ := newCheckpointTestHandler(t, CheckpointOptions{})
	registration.store.mu.Lock()
	run := registration.store.runs[registered.RunID]
	run.RunExpiry = time.Date(2026, 8, 13, 10, 0, 30, 0, time.UTC)
	registration.store.runs[registered.RunID] = run
	registration.store.mu.Unlock()
	registration.now = func() time.Time { return time.Date(2026, 8, 13, 10, 0, 31, 0, time.UTC) }

	if _, err := registration.VerifyIngestToken(registered.IngestToken); err == nil {
		t.Fatal("VerifyIngestToken accepted an expired Run")
	}
	response := postCheckpoint(t, handler.Routes(), registered.RunID, registered.IngestToken, CheckpointRequest{
		Sequence: "1", Type: "run_started",
	})
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("expired Run status = %d", response.Code)
	}
}

func TestCheckpointByteCapacityIsBoundedAndReleased(t *testing.T) {
	handler, registration, registered, _ := newCheckpointTestHandler(t, CheckpointOptions{
		MaxBodyBytes: 1024, CapacityBytesPerRun: 5000,
	})
	first := postCheckpoint(t, handler.Routes(), registered.RunID, registered.IngestToken, CheckpointRequest{
		Sequence: "1", Type: "run_started",
	})
	if first.Code != http.StatusCreated {
		t.Fatalf("first status = %d", first.Code)
	}
	second := postCheckpoint(t, handler.Routes(), registered.RunID, registered.IngestToken, CheckpointRequest{
		Sequence: "2", Type: "tool_started",
	})
	if second.Code != http.StatusServiceUnavailable {
		t.Fatalf("capacity status = %d", second.Code)
	}
	if _, err := registration.FinishRun(registered.RunID); err != nil {
		t.Fatalf("FinishRun: %v", err)
	}
	registration.store.mu.RLock()
	defer registration.store.mu.RUnlock()
	if registration.store.checkpointBytes != 0 || registration.store.checkpoints[registered.RunID] != nil {
		t.Fatalf("retained bytes=%d state=%v", registration.store.checkpointBytes, registration.store.checkpoints[registered.RunID])
	}
}

func TestCheckpointFailureDoesNotConsumeSequence(t *testing.T) {
	clockCalls := 0
	handler, _, registered, _ := newCheckpointTestHandler(t, CheckpointOptions{
		Clock: func() (CheckpointReceiptTime, error) {
			clockCalls++
			if clockCalls == 1 {
				return CheckpointReceiptTime{}, errors.New("clock unavailable")
			}
			return CheckpointReceiptTime{MonotonicNS: 100, UnixNS: 200}, nil
		},
	})
	input := CheckpointRequest{Sequence: "1", IdempotencyKey: "retry-after-failure", Type: "run_started"}
	failed := postCheckpoint(t, handler.Routes(), registered.RunID, registered.IngestToken, input)
	if failed.Code != http.StatusServiceUnavailable || failed.Header().Get("Retry-After") != "1" {
		t.Fatalf("failed status=%d retry=%q", failed.Code, failed.Header().Get("Retry-After"))
	}
	retried := postCheckpoint(t, handler.Routes(), registered.RunID, registered.IngestToken, input)
	if retried.Code != http.StatusCreated || decodeCheckpoint(t, retried).Sequence != "1" {
		t.Fatalf("retry status = %d, body = %s", retried.Code, retried.Body.String())
	}
}

func TestCheckpointRejectsTerminatingRun(t *testing.T) {
	handler, registration, registered, _ := newCheckpointTestHandler(t, CheckpointOptions{})
	if _, started, err := registration.store.beginTermination(registered.RunID); err != nil || !started {
		t.Fatalf("beginTermination: started=%v err=%v", started, err)
	}
	t.Cleanup(func() { registration.store.abortTermination(registered.RunID) })
	if _, err := registration.VerifyIngestToken(registered.IngestToken); err == nil {
		t.Fatal("VerifyIngestToken accepted a terminating Run")
	}
	response := postCheckpoint(t, handler.Routes(), registered.RunID, registered.IngestToken, CheckpointRequest{
		Sequence: "1", Type: "run_finished",
	})
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("terminating Run status = %d", response.Code)
	}
}

func newCheckpointTestHandler(t *testing.T, options CheckpointOptions) (*CheckpointHandler, *RegistrationHandler, RegisterResponse, *testScopeMap) {
	t.Helper()
	scopeMap := &testScopeMap{}
	manager, err := scope.NewManager(scopeMap, testResolver{ids: map[string]uint64{"/agent/leaf": 42}}, testProbe{})
	if err != nil {
		t.Fatalf("scope.NewManager: %v", err)
	}
	now := time.Date(2026, 8, 13, 10, 0, 0, 0, time.UTC)
	registration, err := NewRegistrationHandler(manager, NewRunStore(), RegistrationOptions{
		Now: func() time.Time { return now }, TokenTTL: time.Minute,
	})
	if err != nil {
		t.Fatalf("NewRegistrationHandler: %v", err)
	}
	registered := registerForLifecycleTest(t, registration, "/agent/leaf")
	if options.Clock == nil {
		options.Clock = func() (CheckpointReceiptTime, error) {
			return CheckpointReceiptTime{MonotonicNS: 100, UnixNS: 200, ErrorNS: 3}, nil
		}
	}
	options.Random = &repeatReader{value: 0x7a}
	handler, err := NewCheckpointHandler(registration, options)
	if err != nil {
		t.Fatalf("NewCheckpointHandler: %v", err)
	}
	return handler, registration, registered, scopeMap
}

func addCheckpointTestRun(t *testing.T, registration *RegistrationHandler, runID string, cgroupID, cookie uint64) AgentRun {
	t.Helper()
	run := AgentRun{
		RunID: runID, CgroupID: cgroupID, InstanceID: registration.instanceID, ScopeCookie: cookie,
		Status: "active", RegisteredAt: registration.now(), RunExpiry: registration.now().Add(time.Hour),
		TokenExpiry: registration.now().Add(time.Minute),
	}
	if err := registration.store.Add(run); err != nil {
		t.Fatalf("add test Run: %v", err)
	}
	return run
}

func postCheckpoint(t *testing.T, handler http.Handler, runID, token string, input CheckpointRequest) *httptest.ResponseRecorder {
	t.Helper()
	return postCheckpointResponse(handler, runID, token, input)
}

func postCheckpointResponse(handler http.Handler, runID, token string, input CheckpointRequest) *httptest.ResponseRecorder {
	payload, _ := json.Marshal(input)
	request := httptest.NewRequest(http.MethodPost, "/ingest/v1/runs/"+runID+"/checkpoints", bytes.NewReader(payload))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Authorization", "Bearer "+token)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	return response
}

func decodeCheckpoint(t *testing.T, response *httptest.ResponseRecorder) Checkpoint {
	t.Helper()
	var record Checkpoint
	if err := json.Unmarshal(response.Body.Bytes(), &record); err != nil {
		t.Fatalf("decode checkpoint: %v", err)
	}
	return record
}

type repeatReader struct {
	mu    sync.Mutex
	value byte
}

func (reader *repeatReader) Read(buffer []byte) (int, error) {
	reader.mu.Lock()
	defer reader.mu.Unlock()
	for index := range buffer {
		buffer[index] = reader.value
		reader.value++
	}
	return len(buffer), nil
}

func checkpointsEqual(first, second Checkpoint) bool {
	firstJSON, _ := json.Marshal(first)
	secondJSON, _ := json.Marshal(second)
	return bytes.Equal(firstJSON, secondJSON)
}
