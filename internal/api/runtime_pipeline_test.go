package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/agentshield/agentshield-ebpf/internal/correlator"
	"github.com/agentshield/agentshield-ebpf/internal/evidence"
	"github.com/agentshield/agentshield-ebpf/internal/killer"
	"github.com/agentshield/agentshield-ebpf/internal/policy"
	"github.com/agentshield/agentshield-ebpf/internal/scope"
	"github.com/agentshield/agentshield-ebpf/internal/store"
	"github.com/agentshield/agentshield-ebpf/internal/stream"
)

func TestRuntimePipelineRegistrationCheckpointCorrelationContainmentAndReopen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "runtime.db")
	database, err := store.OpenSQLite(path, store.SQLiteOptions{})
	if errors.Is(err, store.ErrSQLiteUnavailable) {
		t.Skip(err)
	}
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	writer, err := store.NewWriter(database, store.WriterOptions{Redactor: store.NewRedactor([]string{"runtime-private-secret"})})
	if err != nil {
		t.Fatal(err)
	}
	defer writer.Close(context.Background())
	hub, err := stream.NewHub(stream.HubOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer hub.Close()
	manager, err := scope.NewManager(&testScopeMap{}, testResolver{ids: map[string]uint64{"/agent/leaf": 42}}, testProbe{})
	if err != nil {
		t.Fatal(err)
	}
	var pipeline *RuntimePipeline
	registration, err := NewRegistrationHandler(manager, NewRunStore(), RegistrationOptions{OnRunChanged: func(run AgentRun) { pipeline.RunChanged(run) }})
	if err != nil {
		t.Fatal(err)
	}
	configured := p3ExecPolicy("runtime.contain", "contain-tool", policy.DecisionDeny, policy.ActionContain, 10)
	configured.Scope = policy.Scope{Type: policy.ScopeGlobal}
	engine, _, err := policy.NewEngine(policy.Bundle{SchemaVersion: policy.SchemaVersion, Policies: []policy.Policy{configured}}, policy.Generation{Revision: 1, Bank: policy.BankA}, policy.Limits{})
	if err != nil {
		t.Fatal(err)
	}
	executor := &fakeContainmentExecutor{result: killer.ResultKilled}
	coordinator, err := NewPolicyCoordinator(registration.Store(), engine, executor)
	if err != nil {
		t.Fatal(err)
	}
	failures := make(chan error, 16)
	pipeline, err = NewRuntimePipeline(RuntimePipelineOptions{Registration: registration, Coordinator: coordinator, Writer: writer, Hub: hub, Overview: NewOverviewState(OverviewStateOptions{}), Redactor: store.NewRedactor([]string{"runtime-private-secret"}), OnError: func(err error) { failures <- err }})
	if err != nil {
		t.Fatal(err)
	}
	defer pipeline.Close(context.Background())
	registered := registerForLifecycleTest(t, registration, "/agent/leaf")
	run, _ := registration.Store().Get(registered.RunID)
	checkpoint, err := NewCheckpointHandler(registration, CheckpointOptions{OnAccepted: pipeline.SubmitCheckpoint})
	if err != nil {
		t.Fatal(err)
	}
	input := CheckpointRequest{Sequence: "1", Type: "tool_started", ToolName: "contain-tool", Summary: "runtime-private-secret"}
	response := postCheckpoint(t, checkpoint.Routes(), registered.RunID, registered.IngestToken, input)
	if response.Code != http.StatusCreated {
		t.Fatalf("checkpoint status=%d body=%s", response.Code, response.Body.String())
	}
	claim := decodeCheckpoint(t, response)
	if replay := postCheckpoint(t, checkpoint.Routes(), registered.RunID, registered.IngestToken, input); replay.Code != http.StatusOK {
		t.Fatalf("replay status=%d", replay.Code)
	}
	event := p3ExecEvent(run, "contain-tool")
	monotonic, _ := strconv.ParseUint(claim.ServerReceivedMonotonicNS, 10, 64)
	unix, _ := strconv.ParseUint(claim.ServerReceivedUnixNS, 10, 64)
	event.ServerReceivedMonotonicNS = monotonic + 1
	event.ServerReceivedUnixNS = unix + 1
	event.ActionResultName = "none"
	if err := pipeline.SubmitKernel(event); err != nil {
		t.Fatal(err)
	}
	if err := pipeline.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(executor.calls) != 1 {
		t.Fatalf("containment calls=%d", len(executor.calls))
	}
	if _, err := registration.FinishRun(run.RunID); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-failures:
		t.Fatal(err)
	default:
	}
	if err := database.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := store.OpenSQLite(path, store.SQLiteOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	provider, err := NewStoredEvidenceProvider(reopened)
	if err != nil {
		t.Fatal(err)
	}
	timeline, err := provider.Evidence(context.Background(), run.RunID)
	if err != nil {
		t.Fatal(err)
	}
	if len(timeline.Items) != 4 {
		t.Fatalf("timeline items=%#v", timeline.Items)
	}
	sources := map[evidence.Source]bool{}
	for _, item := range timeline.Items {
		sources[item.Source] = true
		if strings.Contains(item.Summary, "runtime-private-secret") {
			t.Fatal("secret persisted")
		}
		if item.Source == evidence.KernelFact && (item.Correlation == nil || item.Correlation.SelectedCheckpoint != claim.CheckpointID || item.Attribution.Status != "exact" || item.Operation.ActionResult != "none") {
			t.Fatalf("kernel evidence=%#v", item)
		}
	}
	for _, source := range []evidence.Source{evidence.AgentClaim, evidence.KernelFact, evidence.PolicyDecision, evidence.ContainmentResult} {
		if !sources[source] {
			t.Fatalf("missing source %s", source)
		}
	}
	handler, err := NewEvidenceHandler(provider, EvidenceHandlerOptions{ReadToken: "runtime-read-token-0123456789"})
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodGet, "/api/v1/evidence/"+run.RunID, nil)
	unauthorized := httptest.NewRecorder()
	handler.Routes().ServeHTTP(unauthorized, request)
	if unauthorized.Code != http.StatusUnauthorized {
		t.Fatalf("unauthorized durable evidence=%d", unauthorized.Code)
	}
	request.Header.Set("Authorization", "Bearer runtime-read-token-0123456789")
	response = httptest.NewRecorder()
	handler.Routes().ServeHTTP(response, request)
	var body evidence.Timeline
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if response.Code != http.StatusOK || response.Header().Get("Cache-Control") != "no-store" || len(body.Items) != 4 {
		t.Fatalf("durable HTTP response=%d items=%d", response.Code, len(body.Items))
	}
}

func TestStoredEvidenceDropsDanglingCheckpointReferences(t *testing.T) {
	database, err := store.OpenSQLite(filepath.Join(t.TempDir(), "retained.db"), store.SQLiteOptions{})
	if errors.Is(err, store.ErrSQLiteUnavailable) {
		t.Skip(err)
	}
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	event := evidence.Event{ID: "retained-kernel", Type: "exec_attempt", Source: evidence.KernelFact,
		ServerMonotonicNS: 1, ServerUnixNS: 2, Summary: "attempt", Operation: &evidence.OperationResult{AttemptObserved: true, ActionResult: "none", Mechanism: "tracepoint/sys_enter_execve"},
		Correlation: &correlator.Result{EventID: "retained-kernel", Attribution: correlator.Attribution{RunID: "retained-run", Status: correlator.AttributionExact},
			SelectedCheckpoint: "pruned-claim", Candidates: []correlator.Candidate{{CheckpointID: "pruned-claim", Score: 60}}, Confidence: 60, CorrelationStatus: "matched", AuthoritativeClock: "server_monotonic_ns"}}
	payload, err := json.Marshal(event)
	if err != nil {
		t.Fatal(err)
	}
	if err := database.AppendBatch([]store.Record{{ID: event.ID, RecordType: event.Type, RunID: "retained-run", Source: store.SourceKernelFact, ServerMonotonicNS: 1, ServerUnixNS: 2, Payload: payload}}); err != nil {
		t.Fatal(err)
	}
	provider, err := NewStoredEvidenceProvider(database)
	if err != nil {
		t.Fatal(err)
	}
	timeline, err := provider.Evidence(context.Background(), "retained-run")
	if err != nil {
		t.Fatal(err)
	}
	correlation := timeline.Items[0].Correlation
	if correlation.SelectedCheckpoint != "" || correlation.Confidence != 0 || len(correlation.Candidates) != 0 || correlation.CorrelationStatus != "checkpoint_outside_snapshot" {
		t.Fatalf("dangling correlation=%+v", correlation)
	}
}

func TestCheckpointHandoffFailureDoesNotConsumeSequenceOrReplayTwice(t *testing.T) {
	calls := 0
	fail := true
	checkpoint, _, run, _ := newCheckpointTestHandler(t, CheckpointOptions{OnAccepted: func(Checkpoint) error {
		calls++
		if fail {
			return ErrRuntimeQueueFull
		}
		return nil
	}})
	input := CheckpointRequest{Sequence: "1", Type: "tool_started", ToolName: "shell"}
	if got := postCheckpoint(t, checkpoint.Routes(), run.RunID, run.IngestToken, input); got.Code != http.StatusServiceUnavailable {
		t.Fatalf("full handoff=%d", got.Code)
	}
	fail = false
	if got := postCheckpoint(t, checkpoint.Routes(), run.RunID, run.IngestToken, input); got.Code != http.StatusCreated {
		t.Fatalf("retry=%d", got.Code)
	}
	if got := postCheckpoint(t, checkpoint.Routes(), run.RunID, run.IngestToken, input); got.Code != http.StatusOK {
		t.Fatalf("replay=%d", got.Code)
	}
	if calls != 2 {
		t.Fatalf("handoff calls=%d", calls)
	}
}

func TestRuntimePipelineHandoffIsBounded(t *testing.T) {
	pipeline := &RuntimePipeline{queue: make(chan runtimeInput, 1)}
	if err := pipeline.SubmitCheckpoint(Checkpoint{}); err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	if err := pipeline.SubmitCheckpoint(Checkpoint{}); !errors.Is(err, ErrRuntimeQueueFull) {
		t.Fatalf("overflow=%v", err)
	}
	if time.Since(start) > time.Second || pipeline.QueueDrops() != 1 {
		t.Fatal("handoff blocked or failed to report gap")
	}
}

type runtimeRecordCapture struct{ records []store.Record }

func (capture *runtimeRecordCapture) AppendBatch(records []store.Record) error {
	capture.records = append(capture.records, records...)
	return nil
}

func TestRuntimePipelinePreservesStoredIdentityAndPublicClockPrecision(t *testing.T) {
	capture := &runtimeRecordCapture{}
	writer, err := store.NewWriter(capture, store.WriterOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer writer.Close(context.Background())
	hub, err := stream.NewHub(stream.HubOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer hub.Close()
	pipeline := &RuntimePipeline{options: RuntimePipelineOptions{Writer: writer, Hub: hub, Redactor: store.NewRedactor([]string{"private-test-secret"}), OnError: func(err error) { t.Error(err) }}}
	run := AgentRun{RunID: "identity-run", InstanceID: 1<<53 + 7, ScopeCookie: 1<<63 + 9}
	event := evidence.Event{ID: "identity-claim", Type: "tool_started", Source: evidence.AgentClaim, ServerMonotonicNS: 1<<53 + 11, ServerUnixNS: 1<<60 + 13, Summary: "private-test-secret"}
	pipeline.emit(run, event, "info", false)
	if err := writer.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(capture.records) != 1 {
		t.Fatalf("records=%d", len(capture.records))
	}
	record := capture.records[0]
	if record.InstanceID != run.InstanceID || record.ScopeCookie != run.ScopeCookie || strings.Contains(string(record.Payload), "private-test-secret") {
		t.Fatalf("identity/redaction=%+v", record)
	}
	var restored evidence.Event
	if err := json.Unmarshal(record.Payload, &restored); err != nil || restored.ServerUnixNS != event.ServerUnixNS {
		t.Fatalf("stored precision=%+v err=%v", restored, err)
	}
	messages, err := hub.Snapshot(context.Background(), stream.Filter{RunID: run.RunID, IncludeAudit: true}, 1, 4<<20)
	if err != nil || len(messages) != 1 {
		t.Fatalf("messages=%d err=%v", len(messages), err)
	}
	var item evidence.Item
	if err := json.Unmarshal(messages[0].Payload, &item); err != nil || item.ServerMonotonicNS != strconv.FormatUint(event.ServerMonotonicNS, 10) || item.ServerUnixNS != strconv.FormatUint(event.ServerUnixNS, 10) {
		t.Fatalf("public clock precision=%+v err=%v", item, err)
	}
}
