package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/agentshield/agentshield-ebpf/internal/scope"
)

func TestFinishRemovesScopeAndKeepsDelayedEventAttribution(t *testing.T) {
	scopeMap := &testScopeMap{}
	manager, err := scope.NewManager(scopeMap, testResolver{ids: map[string]uint64{
		"/agent/leaf": 42,
	}}, testProbe{})
	if err != nil {
		t.Fatalf("scope.NewManager: %v", err)
	}
	now := time.Date(2026, 7, 27, 10, 0, 0, 0, time.UTC)
	handler, err := NewRegistrationHandler(manager, NewRunStore(), RegistrationOptions{
		Now:          func() time.Time { return now },
		TombstoneTTL: time.Minute,
	})
	if err != nil {
		t.Fatalf("NewRegistrationHandler: %v", err)
	}
	registered := registerForLifecycleTest(t, handler, "/agent/leaf")
	instanceID, _ := strconv.ParseUint(registered.InstanceID, 10, 64)
	scopeCookie, _ := strconv.ParseUint(registered.ScopeCookie, 10, 64)
	cgroupID, _ := strconv.ParseUint(registered.CgroupID, 10, 64)

	response := finishForLifecycleTest(t, handler, registered.RunID)
	if response.Code != http.StatusOK {
		t.Fatalf("finish status = %d, body = %s", response.Code, response.Body.String())
	}
	var finished FinishResponse
	if err := json.Unmarshal(response.Body.Bytes(), &finished); err != nil {
		t.Fatalf("decode finish response: %v", err)
	}
	if finished.RunID != registered.RunID || finished.Status != "finished" {
		t.Fatalf("finish response = %+v", finished)
	}
	if _, exists := scopeMap.values[cgroupID]; exists {
		t.Fatal("scope map entry remained after finish")
	}
	if _, err := handler.VerifyIngestToken(registered.IngestToken); err == nil {
		t.Fatal("finished Run retained ingest access")
	}

	attribution := handler.AttributeEvent(instanceID, scopeCookie)
	if attribution.Status != AttributionExact || attribution.RunID != registered.RunID ||
		attribution.RunStatus != "finished" {
		t.Fatalf("delayed event attribution = %+v", attribution)
	}

	retry := finishForLifecycleTest(t, handler, registered.RunID)
	if retry.Code != http.StatusOK {
		t.Fatalf("idempotent finish status = %d, body = %s", retry.Code, retry.Body.String())
	}

	now = now.Add(time.Minute)
	if attribution := handler.AttributeEvent(instanceID, scopeCookie); attribution.Status != AttributionStale ||
		attribution.RunID != "" {
		t.Fatalf("expired tombstone attribution = %+v, want stale without Run", attribution)
	}
	if attribution := handler.AttributeEvent(instanceID+1, scopeCookie); attribution.Status != AttributionUnknown {
		t.Fatalf("foreign instance attribution = %+v, want unknown", attribution)
	}
}

func TestTombstoneCapacityEvictsOldestIdentity(t *testing.T) {
	scopeMap := &testScopeMap{}
	manager, err := scope.NewManager(scopeMap, testResolver{ids: map[string]uint64{
		"/agent/one": 41,
		"/agent/two": 42,
	}}, testProbe{})
	if err != nil {
		t.Fatalf("scope.NewManager: %v", err)
	}
	now := time.Date(2026, 7, 27, 11, 0, 0, 0, time.UTC)
	handler, err := NewRegistrationHandler(manager, NewRunStore(), RegistrationOptions{
		Now:                 func() time.Time { return now },
		TombstoneMaxEntries: 1,
	})
	if err != nil {
		t.Fatalf("NewRegistrationHandler: %v", err)
	}

	first := registerForLifecycleTest(t, handler, "/agent/one")
	if response := finishForLifecycleTest(t, handler, first.RunID); response.Code != http.StatusOK {
		t.Fatalf("finish first status = %d", response.Code)
	}
	now = now.Add(time.Second)
	second := registerForLifecycleTest(t, handler, "/agent/two")
	if response := finishForLifecycleTest(t, handler, second.RunID); response.Code != http.StatusOK {
		t.Fatalf("finish second status = %d", response.Code)
	}

	firstInstance, _ := strconv.ParseUint(first.InstanceID, 10, 64)
	firstCookie, _ := strconv.ParseUint(first.ScopeCookie, 10, 64)
	secondCookie, _ := strconv.ParseUint(second.ScopeCookie, 10, 64)
	if got := handler.AttributeEvent(firstInstance, firstCookie); got.Status != AttributionStale {
		t.Fatalf("oldest attribution = %+v, want stale after capacity eviction", got)
	}
	if got := handler.AttributeEvent(firstInstance, secondCookie); got.Status != AttributionExact ||
		got.RunID != second.RunID {
		t.Fatalf("newest attribution = %+v, want exact second Run", got)
	}
}

func TestSequentialCgroupReuseKeepsRunIdentitiesSeparate(t *testing.T) {
	scopeMap := &testScopeMap{}
	manager, err := scope.NewManager(scopeMap, testResolver{ids: map[string]uint64{
		"/agent/reused": 42,
	}}, testProbe{})
	if err != nil {
		t.Fatalf("scope.NewManager: %v", err)
	}
	now := time.Date(2026, 7, 28, 10, 0, 0, 0, time.UTC)
	handler, err := NewRegistrationHandler(manager, NewRunStore(), RegistrationOptions{
		Now: func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("NewRegistrationHandler: %v", err)
	}

	first := registerForLifecycleTest(t, handler, "/agent/reused")
	if response := finishForLifecycleTest(t, handler, first.RunID); response.Code != http.StatusOK {
		t.Fatalf("finish first status = %d, body = %s", response.Code, response.Body.String())
	}
	now = now.Add(time.Second)
	second := registerForLifecycleTest(t, handler, "/agent/reused")
	if first.ScopeCookie == second.ScopeCookie {
		t.Fatal("sequential registrations reused a scope cookie")
	}

	instanceID, _ := strconv.ParseUint(first.InstanceID, 10, 64)
	firstCookie, _ := strconv.ParseUint(first.ScopeCookie, 10, 64)
	secondCookie, _ := strconv.ParseUint(second.ScopeCookie, 10, 64)
	if got := handler.AttributeEvent(instanceID, firstCookie); got.Status != AttributionExact ||
		got.RunID != first.RunID || got.RunStatus != "finished" {
		t.Fatalf("old event attribution = %+v", got)
	}
	if got := handler.AttributeEvent(instanceID, secondCookie); got.Status != AttributionExact ||
		got.RunID != second.RunID || got.RunStatus != "active" {
		t.Fatalf("new event attribution = %+v", got)
	}
	if got := scopeMap.values[42]; got.ScopeCookie != secondCookie {
		t.Fatalf("reused cgroup map value = %+v, want second cookie %d", got, secondCookie)
	}
}

func TestCleanupExpiredRunsUsesRunLifetimeNotIngestTokenLifetime(t *testing.T) {
	scopeMap := &testScopeMap{}
	manager, err := scope.NewManager(scopeMap, testResolver{ids: map[string]uint64{
		"/agent/leaf": 42,
	}}, testProbe{})
	if err != nil {
		t.Fatalf("scope.NewManager: %v", err)
	}
	now := time.Date(2026, 7, 27, 12, 0, 0, 0, time.UTC)
	store := NewRunStore()
	handler, err := NewRegistrationHandler(manager, store, RegistrationOptions{
		Now:      func() time.Time { return now },
		TokenTTL: time.Second,
		RunTTL:   2 * time.Second,
	})
	if err != nil {
		t.Fatalf("NewRegistrationHandler: %v", err)
	}
	registered := registerForLifecycleTest(t, handler, "/agent/leaf")
	now = now.Add(time.Second)

	if err := handler.CleanupExpiredRuns(); err != nil {
		t.Fatalf("CleanupExpiredRuns: %v", err)
	}
	run, exists := store.Get(registered.RunID)
	if !exists || run.Status != "active" || !run.EndedAt.IsZero() {
		t.Fatalf("Run ended with its ingest token: %+v, exists=%v", run, exists)
	}
	if len(scopeMap.values) != 1 {
		t.Fatalf("scope map after token expiry = %v, want active scope", scopeMap.values)
	}
	if _, err := handler.VerifyIngestToken(registered.IngestToken); err == nil {
		t.Fatal("expired ingest token retained access")
	}

	now = now.Add(time.Second)
	if err := handler.CleanupExpiredRuns(); err != nil {
		t.Fatalf("CleanupExpiredRuns at Run expiry: %v", err)
	}
	run, exists = store.Get(registered.RunID)
	if !exists || run.Status != "expired" || run.EndedAt.IsZero() {
		t.Fatalf("expired Run = %+v, exists=%v", run, exists)
	}
	if len(scopeMap.values) != 0 {
		t.Fatalf("scope map after TTL cleanup = %v", scopeMap.values)
	}
}

func TestFinishRollsBackStateWhenScopeRemovalFails(t *testing.T) {
	store := NewRunStore()
	registeredAt := time.Date(2026, 7, 27, 13, 0, 0, 0, time.UTC)
	if err := store.Add(AgentRun{
		RunID:        "run-1",
		CgroupID:     42,
		InstanceID:   10,
		ScopeCookie:  11,
		Status:       "active",
		RegisteredAt: registeredAt,
		TokenExpiry:  registeredAt.Add(time.Minute),
	}); err != nil {
		t.Fatalf("store.Add: %v", err)
	}
	handler, err := NewRegistrationHandler(failingUnregisterRegistrar{}, store, RegistrationOptions{
		Now: func() time.Time { return registeredAt },
	})
	if err != nil {
		t.Fatalf("NewRegistrationHandler: %v", err)
	}

	if _, err := handler.FinishRun("run-1"); err == nil {
		t.Fatal("FinishRun returned nil after scope removal failure")
	}
	run, _ := store.Get("run-1")
	if run.Status != "active" || !run.EndedAt.IsZero() {
		t.Fatalf("Run changed after failed scope removal: %+v", run)
	}
	if attribution := store.attribute(run.scopeIdentity(), run.InstanceID, registeredAt); attribution.Status != AttributionExact {
		t.Fatalf("live attribution was lost after rollback: %+v", attribution)
	}
}

func TestCompletingOldRunPreservesReplacementCgroupIndex(t *testing.T) {
	store := NewRunStore()
	now := time.Date(2026, 8, 13, 9, 30, 0, 0, time.UTC)
	old := AgentRun{
		RunID: "old-run", CgroupID: 42, InstanceID: 1, ScopeCookie: 2,
		Status: "active", RegisteredAt: now, RunExpiry: now.Add(time.Hour),
	}
	if err := store.Add(old); err != nil {
		t.Fatalf("add old Run: %v", err)
	}
	if _, begun, err := store.beginTermination(old.RunID); err != nil || !begun {
		t.Fatalf("begin old termination: begun=%v error=%v", begun, err)
	}

	store.mu.Lock()
	delete(store.activeByCgroup, old.CgroupID)
	store.mu.Unlock()
	replacement := AgentRun{
		RunID: "new-run", CgroupID: 42, InstanceID: 1, ScopeCookie: 3,
		Status: "active", RegisteredAt: now.Add(time.Second), RunExpiry: now.Add(time.Hour),
	}
	if err := store.Add(replacement); err != nil {
		t.Fatalf("add replacement Run: %v", err)
	}
	if _, err := store.completeTermination(old.RunID, "finished", now.Add(2*time.Second), time.Minute, 10); err != nil {
		t.Fatalf("complete old termination: %v", err)
	}

	failed, transitioned, exists := store.FailScope(42, scope.ViolationMemberEscape)
	if !exists || !transitioned || failed.RunID != replacement.RunID {
		t.Fatalf("FailScope replacement = run=%+v exists=%v transitioned=%v", failed, exists, transitioned)
	}
}

func TestRunStoreRejectsScopeIdentityCollision(t *testing.T) {
	store := NewRunStore()
	now := time.Date(2026, 7, 27, 14, 0, 0, 0, time.UTC)
	first := AgentRun{
		RunID:        "run-1",
		CgroupID:     41,
		InstanceID:   10,
		ScopeCookie:  11,
		Status:       "active",
		RegisteredAt: now,
	}
	if err := store.Add(first); err != nil {
		t.Fatalf("add first Run: %v", err)
	}
	second := first
	second.RunID = "run-2"
	second.CgroupID = 42
	if err := store.Add(second); !errors.Is(err, ErrScopeIdentityCollision) {
		t.Fatalf("collision error = %v, want ErrScopeIdentityCollision", err)
	}
}

type failingUnregisterRegistrar struct{}

func (failingUnregisterRegistrar) Register(context.Context, scope.Target, scope.Value) (scope.Registration, error) {
	return scope.Registration{}, errors.New("not used")
}

func (failingUnregisterRegistrar) Unregister(uint64) error {
	return errors.New("scope map delete failed")
}

func registerForLifecycleTest(t *testing.T, handler *RegistrationHandler, path string) RegisterResponse {
	t.Helper()
	response := postJSON(t, handler.Routes(), map[string]any{
		"agent_name":  "lifecycle-test",
		"cgroup_path": path,
	})
	if response.Code != http.StatusCreated {
		t.Fatalf("register status = %d, body = %s", response.Code, response.Body.String())
	}
	var output RegisterResponse
	if err := json.Unmarshal(response.Body.Bytes(), &output); err != nil {
		t.Fatalf("decode register response: %v", err)
	}
	return output
}

func finishForLifecycleTest(t *testing.T, handler *RegistrationHandler, runID string) *httptest.ResponseRecorder {
	t.Helper()
	request := httptest.NewRequest(http.MethodPost, "/api/v1/agents/"+runID+"/finish", nil)
	response := httptest.NewRecorder()
	handler.Routes().ServeHTTP(response, request)
	return response
}
