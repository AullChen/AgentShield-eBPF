package api

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/agentshield/agentshield-ebpf/internal/scope"
)

type monitorInspector struct {
	state scope.State
	err   error
}

func (inspector monitorInspector) Inspect(*scope.Handle, int) (scope.State, error) {
	return inspector.state, inspector.err
}

func TestMonitorScopesEmitsViolationAndFailsRun(t *testing.T) {
	scopeMap := &testScopeMap{}
	manager, err := scope.NewManager(scopeMap, testResolver{ids: map[string]uint64{
		"/agent/leaf": 42,
	}}, testProbe{})
	if err != nil {
		t.Fatalf("scope.NewManager: %v", err)
	}
	registration, err := manager.Register(context.Background(), scope.Target{
		Path:    "/agent/leaf",
		RootPID: 42,
	}, scope.Value{
		InstanceID:  9007199254740993,
		ScopeCookie: 9007199254740994,
	})
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	store := NewRunStore()
	if err := store.Add(AgentRun{
		RunID:       "run-1",
		CgroupID:    registration.CgroupID,
		InstanceID:  registration.Value.InstanceID,
		ScopeCookie: registration.Value.ScopeCookie,
		Status:      "active",
	}); err != nil {
		t.Fatalf("store.Add: %v", err)
	}
	handler := newScopeMonitorHandler(t, manager, store)

	var events []ScopeViolationEvent
	observedAt := time.Date(2026, 7, 24, 13, 0, 0, 0, time.UTC)
	err = MonitorScopesOnce(manager, monitorInspector{state: scope.State{
		ChildCgroups: []string{registration.Path + "/child"},
		RootPIDPath:  "/escaped",
	}}, handler, observedAt, func(event ScopeViolationEvent) error {
		events = append(events, event)
		return nil
	})
	if err != nil {
		t.Fatalf("MonitorScopesOnce: %v", err)
	}
	if len(events) != 2 {
		t.Fatalf("events = %+v, want child and escape violations", events)
	}
	if events[0].EventType != "scope_violation" || events[0].CgroupID != "42" ||
		events[0].InstanceID != "9007199254740993" ||
		events[0].ScopeCookie != "9007199254740994" {
		t.Fatalf("event identity = %+v", events[0])
	}
	payload, err := json.Marshal(events[0])
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	if string(payload) == "" {
		t.Fatal("scope violation did not encode")
	}
	run, _ := store.Get("run-1")
	if run.Status != "failed" || run.StatusReason == "" || !run.EndedAt.Equal(observedAt) {
		t.Fatalf("run status = %q/%q, want failed with reason", run.Status, run.StatusReason)
	}
	if len(manager.ActiveIDs()) != 0 {
		t.Fatalf("violated scope remained active: %v", manager.ActiveIDs())
	}
	if attribution := store.attribute(run.scopeIdentity(), handler.instanceID, observedAt); attribution.Status != AttributionExact ||
		attribution.RunID != run.RunID || attribution.RunStatus != "failed" {
		t.Fatalf("delayed violation attribution = %+v", attribution)
	}

	if err := MonitorScopesOnce(manager, monitorInspector{state: scope.State{
		ChildCgroups: []string{registration.Path + "/child"},
		RootPIDPath:  "/escaped",
	}}, handler, time.Date(2026, 7, 24, 13, 0, 1, 0, time.UTC), func(event ScopeViolationEvent) error {
		events = append(events, event)
		return nil
	}); err != nil {
		t.Fatalf("second MonitorScopesOnce: %v", err)
	}
	if len(events) != 2 {
		t.Fatalf("events after repeated observation = %d, want no duplicates", len(events))
	}
}

func TestMonitorScopesFailsClosedWhenInspectionErrors(t *testing.T) {
	scopeMap := &testScopeMap{}
	manager, err := scope.NewManager(scopeMap, testResolver{ids: map[string]uint64{
		"/agent/leaf": 42,
	}}, testProbe{})
	if err != nil {
		t.Fatalf("scope.NewManager: %v", err)
	}
	registration, err := manager.Register(context.Background(), scope.Target{
		Path:    "/agent/leaf",
		RootPID: 42,
	}, scope.Value{
		InstanceID:  1,
		ScopeCookie: 2,
	})
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	store := NewRunStore()
	if err := store.Add(AgentRun{
		RunID:       "run-1",
		CgroupID:    registration.CgroupID,
		InstanceID:  registration.Value.InstanceID,
		ScopeCookie: registration.Value.ScopeCookie,
		Status:      "active",
	}); err != nil {
		t.Fatalf("store.Add: %v", err)
	}
	handler := newScopeMonitorHandler(t, manager, store)

	var events []ScopeViolationEvent
	err = MonitorScopesOnce(
		manager,
		monitorInspector{err: errors.New("root PID disappeared")},
		handler,
		time.Date(2026, 7, 26, 1, 0, 0, 0, time.UTC),
		func(event ScopeViolationEvent) error {
			events = append(events, event)
			return nil
		},
	)
	if err != nil {
		t.Fatalf("MonitorScopesOnce: %v", err)
	}
	if len(events) != 1 || events[0].Reason != scope.ViolationInspectionFailed {
		t.Fatalf("events = %+v, want one inspection failure", events)
	}
	run, _ := store.Get("run-1")
	if run.Status != "failed" || run.StatusReason != scope.ViolationInspectionFailed {
		t.Fatalf("run status = %q/%q, want failed inspection", run.Status, run.StatusReason)
	}
}

func TestMonitorScopesRetriesWhenViolationEmissionFails(t *testing.T) {
	scopeMap := &testScopeMap{}
	manager, err := scope.NewManager(scopeMap, testResolver{ids: map[string]uint64{"/agent/leaf": 42}}, testProbe{})
	if err != nil {
		t.Fatal(err)
	}
	registration, err := manager.Register(context.Background(), scope.Target{Path: "/agent/leaf", RootPID: 42}, scope.Value{
		InstanceID: 1, ScopeCookie: 2,
	})
	if err != nil {
		t.Fatal(err)
	}
	store := NewRunStore()
	if err := store.Add(AgentRun{
		RunID: "run-1", CgroupID: registration.CgroupID, InstanceID: 1, ScopeCookie: 2, Status: "active",
	}); err != nil {
		t.Fatal(err)
	}
	handler := newScopeMonitorHandler(t, manager, store)
	inspector := monitorInspector{state: scope.State{RootPIDPath: "/escaped"}}
	if err := MonitorScopesOnce(manager, inspector, handler, time.Now(), func(ScopeViolationEvent) error {
		return errors.New("sink unavailable")
	}); err == nil {
		t.Fatal("emitter failure was ignored")
	}
	if run, _ := store.Get("run-1"); run.Status != "active" {
		t.Fatalf("Run status after emitter failure = %q, want active for retry", run.Status)
	}
	emitted := 0
	if err := MonitorScopesOnce(manager, inspector, handler, time.Now(), func(ScopeViolationEvent) error {
		emitted++
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if emitted != 1 {
		t.Fatalf("retried events = %d, want 1", emitted)
	}
	if run, _ := store.Get("run-1"); run.Status != "failed" {
		t.Fatalf("Run status after successful retry = %q", run.Status)
	}
}

func newScopeMonitorHandler(t *testing.T, manager *scope.Manager, store *RunStore) *RegistrationHandler {
	t.Helper()
	handler, err := NewRegistrationHandler(manager, store, RegistrationOptions{})
	if err != nil {
		t.Fatal(err)
	}
	return handler
}
