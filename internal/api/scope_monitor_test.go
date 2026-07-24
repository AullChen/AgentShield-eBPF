package api

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/agentshield/agentshield-ebpf/internal/scope"
)

type monitorInspector struct {
	state scope.State
}

func (inspector monitorInspector) Inspect(*scope.Handle, int) (scope.State, error) {
	return inspector.state, nil
}

func TestMonitorScopesEmitsViolationAndFailsRun(t *testing.T) {
	scopeMap := &testScopeMap{}
	manager, err := scope.NewManager(scopeMap, testResolver{}, testProbe{})
	if err != nil {
		t.Fatalf("scope.NewManager: %v", err)
	}
	registration, err := manager.Register(context.Background(), scope.Target{PID: 42}, scope.Value{
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

	var events []ScopeViolationEvent
	err = MonitorScopesOnce(manager, monitorInspector{state: scope.State{
		ChildCgroups: []string{registration.Path + "/child"},
		RootPIDPath:  "/escaped",
	}}, store, time.Date(2026, 7, 24, 13, 0, 0, 0, time.UTC), func(event ScopeViolationEvent) error {
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
	if run.Status != "failed" || run.StatusReason == "" {
		t.Fatalf("run status = %q/%q, want failed with reason", run.Status, run.StatusReason)
	}
}
