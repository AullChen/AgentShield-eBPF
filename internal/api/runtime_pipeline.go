package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"strconv"
	"sync"
	"sync/atomic"

	"github.com/agentshield/agentshield-ebpf/internal/correlator"
	"github.com/agentshield/agentshield-ebpf/internal/events"
	"github.com/agentshield/agentshield-ebpf/internal/evidence"
	"github.com/agentshield/agentshield-ebpf/internal/policy"
	"github.com/agentshield/agentshield-ebpf/internal/store"
	"github.com/agentshield/agentshield-ebpf/internal/stream"
)

var ErrRuntimeQueueFull = errors.New("runtime pipeline queue is full or closed")

type RuntimePipelineOptions struct {
	Registration *RegistrationHandler
	Coordinator  *PolicyCoordinator
	Writer       *store.Writer
	Hub          *stream.Hub
	Overview     *OverviewState
	Redactor     store.Redactor
	OnError      func(error)
}

type runtimeInput struct {
	kernel     *events.KernelEvent
	checkpoint *Checkpoint
}

// RuntimePipeline serializes bounded checkpoint/kernel fan-in. Policy and
// cgroup.kill I/O runs in its worker, never on the ring-buffer read goroutine.
type RuntimePipeline struct {
	options  RuntimePipelineOptions
	mu       sync.RWMutex
	closing  bool
	queue    chan runtimeInput
	done     chan struct{}
	ctx      context.Context
	cancel   context.CancelFunc
	drops    atomic.Uint64
	sequence uint64
	claims   []correlator.Checkpoint
}

func NewRuntimePipeline(options RuntimePipelineOptions) (*RuntimePipeline, error) {
	if options.Registration == nil || options.Coordinator == nil || options.Writer == nil || options.Hub == nil || options.Overview == nil {
		return nil, errors.New("runtime requires registration, coordinator, writer, hub, and overview")
	}
	ctx, cancel := context.WithCancel(context.Background())
	pipeline := &RuntimePipeline{options: options, queue: make(chan runtimeInput, 256), done: make(chan struct{}), ctx: ctx, cancel: cancel}
	go pipeline.run()
	return pipeline, nil
}

func (pipeline *RuntimePipeline) submit(input runtimeInput) error {
	pipeline.mu.RLock()
	defer pipeline.mu.RUnlock()
	if !pipeline.closing {
		select {
		case pipeline.queue <- input:
			return nil
		default:
		}
	}
	pipeline.drops.Add(1)
	return ErrRuntimeQueueFull
}

func (pipeline *RuntimePipeline) SubmitKernel(event events.KernelEvent) error {
	return pipeline.submit(runtimeInput{kernel: &event})
}

func (pipeline *RuntimePipeline) SubmitCheckpoint(checkpoint Checkpoint) error {
	copy := cloneCheckpoint(checkpoint)
	return pipeline.submit(runtimeInput{checkpoint: &copy})
}

func (pipeline *RuntimePipeline) QueueDrops() uint64 { return pipeline.drops.Load() }

func (pipeline *RuntimePipeline) RunChanged(run AgentRun) {
	if err := pipeline.options.Overview.UpsertRun(OverviewRunInput{RunID: run.RunID, Label: run.AgentName, Status: run.Status, StartedAt: run.RegisteredAt}); err != nil {
		pipeline.report(err)
	}
	receipt, err := captureCheckpointReceiptTime()
	if err != nil {
		pipeline.report(err)
		return
	}
	// Lifecycle metadata contains no token/hash, prompt, or Agent claim.
	if !pipeline.options.Writer.Submit(store.Record{ID: "run-" + run.RunID + "-" + run.Status, RecordType: "run_lifecycle", RunID: run.RunID,
		Source: store.SourceDiagnostic, ServerMonotonicNS: receipt.MonotonicNS, ServerUnixNS: receipt.UnixNS, InstanceID: run.InstanceID,
		ScopeCookie: run.ScopeCookie, Summary: "Run " + run.Status, Labels: map[string]string{"status": run.Status}}) {
		pipeline.report(errors.New("Run lifecycle storage queue rejected record"))
	}
}

func (pipeline *RuntimePipeline) Close(ctx context.Context) error {
	if ctx == nil {
		return errors.New("runtime close context is required")
	}
	pipeline.mu.Lock()
	if !pipeline.closing {
		pipeline.closing = true
		close(pipeline.queue)
	}
	pipeline.mu.Unlock()
	select {
	case <-pipeline.done:
		pipeline.cancel()
		return nil
	case <-ctx.Done():
		pipeline.cancel()
		return ctx.Err()
	}
}

func (pipeline *RuntimePipeline) run() {
	defer close(pipeline.done)
	for input := range pipeline.queue {
		if input.checkpoint != nil {
			pipeline.processCheckpoint(*input.checkpoint)
		}
		if input.kernel != nil {
			pipeline.processKernel(*input.kernel)
		}
	}
}

func (pipeline *RuntimePipeline) processCheckpoint(checkpoint Checkpoint) {
	run, exists := pipeline.options.Registration.store.Get(checkpoint.RunID)
	if !exists {
		pipeline.report(errors.New("checkpoint has no registered Run identity"))
		return
	}
	monotonic, _ := strconv.ParseUint(checkpoint.ServerReceivedMonotonicNS, 10, 64)
	unix, _ := strconv.ParseUint(checkpoint.ServerReceivedUnixNS, 10, 64)
	sequence, _ := strconv.ParseUint(checkpoint.Sequence, 10, 64)
	pipeline.claims = append(pipeline.claims, correlator.Checkpoint{CheckpointID: checkpoint.CheckpointID, RunID: checkpoint.RunID,
		ServerMonotonicNS: monotonic, Sequence: sequence, Type: checkpoint.Type, Phase: checkpoint.Phase, ToolName: checkpoint.ToolName})
	if len(pipeline.claims) > 1024 {
		pipeline.claims = pipeline.claims[1:]
	}
	pipeline.emit(run, evidence.Event{ID: checkpoint.CheckpointID, Type: checkpoint.Type, Source: evidence.AgentClaim,
		ServerMonotonicNS: monotonic, ServerUnixNS: unix, Summary: checkpoint.Summary}, "info", false)
}

func (pipeline *RuntimePipeline) processKernel(event events.KernelEvent) {
	pipeline.sequence++
	id := fmt.Sprintf("kernel-%d-%d", event.InstanceID, pipeline.sequence)
	attribution := pipeline.options.Registration.AttributeEvent(event.InstanceID, event.ScopeCookie)
	if attribution.RunID == "" {
		pipeline.report(errors.New("kernel event has no registered Run attribution"))
		return
	}
	registered, exists := pipeline.options.Registration.store.Get(attribution.RunID)
	if !exists || registered.CgroupID != event.CgroupID {
		pipeline.report(errors.New("kernel event cgroup does not match registered identity"))
		return
	}
	resolver := func(_, _, _ uint64) correlator.Attribution {
		return correlator.Attribution{RunID: attribution.RunID, RunStatus: attribution.RunStatus, Status: correlator.AttributionStatus(attribution.Status)}
	}
	matcher, _ := correlator.New(resolver, correlator.Options{})
	claims := make([]correlator.Checkpoint, 0, 64)
	for index := len(pipeline.claims) - 1; index >= 0 && len(claims) < 64; index-- {
		if pipeline.claims[index].RunID == attribution.RunID {
			claims = append(claims, pipeline.claims[index])
		}
	}
	correlation := matcher.Correlate(correlator.KernelEvent{EventID: id, InstanceID: event.InstanceID, ScopeCookie: event.ScopeCookie,
		ServerMonotonicNS: event.ServerReceivedMonotonicNS, PID: event.PID, TGID: event.TGID, EventType: event.EventTypeName,
		ToolName: filepath.Base(event.Data)}, claims)
	mechanism := kernelMechanism(event.EventTypeName, map[string]any{"family_name": event.AddressFamilyName})
	severity := "info"
	if event.ActionResult == events.ActionResultBlocked {
		severity = "high"
	}
	summary := evidenceSummary(stream.Message{EventType: event.EventTypeName}, map[string]any{"data": event.Data, "dst_ip": event.DestinationIP, "dst_port": strconv.FormatUint(uint64(event.DestinationPort), 10)})
	pipeline.emit(registered, evidence.Event{ID: id, Type: event.EventTypeName, Source: evidence.KernelFact,
		ServerMonotonicNS: event.ServerReceivedMonotonicNS, ServerUnixNS: event.ServerReceivedUnixNS,
		Summary: summary, Attribution: &evidence.Attribution{Status: string(attribution.Status), RunID: attribution.RunID,
			RunStatus: attribution.RunStatus, Basis: "instance_id+scope_cookie"}, Correlation: &correlation,
		Operation: &evidence.OperationResult{AttemptObserved: true, ActionResult: event.ActionResultName, Mechanism: mechanism}}, severity, event.Action == events.ActionAudit)
	_ = pipeline.options.Overview.ObserveEvent(OverviewEventInput{RunID: attribution.RunID, Blocked: event.ActionResult == events.ActionResultBlocked})
	derived, err := pipeline.options.Coordinator.ProcessAuditEvent(pipeline.ctx, event)
	if errors.Is(err, ErrPolicyEventNotActiveRun) {
		return
	}
	if err != nil {
		pipeline.report(err)
		return
	}
	for _, record := range derived {
		receipt, clockErr := captureCheckpointReceiptTime()
		if clockErr != nil {
			pipeline.report(clockErr)
			return
		}
		switch typed := record.(type) {
		case policy.AuditDecisionRecord:
			if typed.Final == nil {
				continue
			}
			final := typed.Final
			mechanism := "post_event"
			if final.Enforced && final.RequestedAction == policy.ActionBlock {
				mechanism = kernelMechanism(event.EventTypeName, map[string]any{"family_name": event.AddressFamilyName})
			}
			_ = pipeline.options.Overview.ObservePolicyHit(attribution.RunID)
			pipeline.emit(registered, evidence.Event{ID: "decision-" + id, Type: "policy_decision", Source: evidence.PolicyDecision,
				ServerMonotonicNS: receipt.MonotonicNS, ServerUnixNS: receipt.UnixNS, Summary: "Policy " + final.PolicyID + " requested " + string(final.RequestedAction),
				Decision: &evidence.Decision{PolicyID: final.PolicyID, RuleID: strconv.FormatUint(uint64(final.RuleID), 10), RequestedAction: string(final.RequestedAction),
					FinalDecision: string(final.Decision), Enforced: final.Enforced, Mechanism: mechanism}}, "medium", false)
		case PolicyContainmentRecord:
			pipeline.emit(registered, evidence.Event{ID: "containment-" + id, Type: "containment_result", Source: evidence.ContainmentResult,
				ServerMonotonicNS: receipt.MonotonicNS, ServerUnixNS: receipt.UnixNS, Summary: "Post-event containment " + string(typed.EnforcementResult),
				Containment: &evidence.Containment{Requested: true, Result: string(typed.EnforcementResult), Method: string(typed.EnforcementMethod),
					TargetIdentity: fmt.Sprintf("cgroup %d; instance %d; scope %d", typed.CgroupID, typed.InstanceID, typed.ScopeCookie), OriginalActionResult: string(typed.SyscallResult)}}, "high", false)
		}
	}
}

func (pipeline *RuntimePipeline) emit(run AgentRun, event evidence.Event, severity string, audit bool) {
	runID := run.RunID
	payload, err := json.Marshal(event)
	if err != nil {
		pipeline.report(err)
		return
	}
	record, err := pipeline.options.Redactor.Apply(store.Record{ID: event.ID, RecordType: event.Type, RunID: runID, Source: store.Source(event.Source),
		ServerMonotonicNS: event.ServerMonotonicNS, ServerUnixNS: event.ServerUnixNS, InstanceID: run.InstanceID, ScopeCookie: run.ScopeCookie,
		Severity: severity, Summary: event.Summary, Payload: payload})
	if err != nil {
		pipeline.report(err)
		return
	}
	if !pipeline.options.Writer.Submit(record) {
		pipeline.report(errors.New("runtime evidence storage queue rejected record"))
	}
	// Stream payload uses decimal clock strings; durable evidence uses Go u64
	// fields which the Evidence provider converts to the public string schema.
	if err := json.Unmarshal(record.Payload, &event); err != nil {
		pipeline.report(err)
		return
	}
	timeline, err := evidence.Build(runID, []evidence.Event{stripCorrelation(event)})
	if err != nil {
		pipeline.report(err)
		return
	}
	streamPayload, _ := json.Marshal(timeline.Items[0])
	_, err = pipeline.options.Hub.Publish(stream.Event{ID: event.ID, Type: event.Type, Source: string(event.Source), RunID: runID, Severity: severity,
		EventType: event.Type, ServerMonotonicNS: event.ServerMonotonicNS, ServerUnixNS: event.ServerUnixNS, Audit: audit, Payload: streamPayload})
	if err != nil {
		pipeline.report(err)
	}
}

func stripCorrelation(event evidence.Event) evidence.Event { event.Correlation = nil; return event }

func (pipeline *RuntimePipeline) report(err error) {
	if pipeline.options.OnError != nil {
		pipeline.options.OnError(err)
	}
}

type StoredEvidenceProvider struct {
	Database  *store.SQLite
	snapshots chan struct{}
}

func NewStoredEvidenceProvider(database *store.SQLite) (*StoredEvidenceProvider, error) {
	if database == nil {
		return nil, errors.New("evidence database is required")
	}
	return &StoredEvidenceProvider{Database: database, snapshots: make(chan struct{}, evidenceSnapshotConcurrency)}, nil
}

func (provider *StoredEvidenceProvider) Evidence(ctx context.Context, runID string) (evidence.Timeline, error) {
	if provider == nil || provider.Database == nil || provider.snapshots == nil {
		return evidence.Timeline{}, errors.New("evidence database is required")
	}
	if ctx == nil {
		return evidence.Timeline{}, errors.New("evidence context is required")
	}
	select {
	case provider.snapshots <- struct{}{}:
		defer func() { <-provider.snapshots }()
	case <-ctx.Done():
		return evidence.Timeline{}, ctx.Err()
	}
	payloads, err := provider.Database.ReadPayloads(ctx, runID, 1000, 4<<20)
	if err != nil {
		return evidence.Timeline{}, err
	}
	items := make([]evidence.Event, 0, len(payloads))
	claims := make(map[string]bool)
	for _, payload := range payloads {
		var event evidence.Event
		if err := json.Unmarshal(payload, &event); err != nil {
			return evidence.Timeline{}, err
		}
		items = append(items, event)
		if event.Source == evidence.AgentClaim {
			claims[event.ID] = true
		}
	}
	for index := range items {
		correlation := items[index].Correlation
		if correlation == nil {
			continue
		}
		missing := correlation.SelectedCheckpoint != "" && !claims[correlation.SelectedCheckpoint]
		kept := correlation.Candidates[:0]
		for _, candidate := range correlation.Candidates {
			if claims[candidate.CheckpointID] {
				kept = append(kept, candidate)
			} else {
				missing = true
			}
		}
		correlation.Candidates = kept
		if missing {
			correlation.SelectedCheckpoint = ""
			correlation.Confidence = 0
			correlation.CorrelationStatus = "checkpoint_outside_snapshot"
		}
	}
	return evidence.Build(runID, items)
}
