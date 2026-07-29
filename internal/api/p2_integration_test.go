package api

import (
	"net/http"
	"strconv"
	"testing"
	"time"

	"github.com/agentshield/agentshield-ebpf/internal/scope"
)

func TestP2LifecycleAcceptance(t *testing.T) {
	const (
		reusedCgroupID = uint64(42)
		hostCgroupID   = uint64(7)
		reusedPath     = "/agent/p2-reused"
	)
	scopeMap := &testScopeMap{}
	manager, err := scope.NewManager(scopeMap, testResolver{ids: map[string]uint64{
		reusedPath: reusedCgroupID,
	}}, testProbe{})
	if err != nil {
		t.Fatalf("scope.NewManager: %v", err)
	}
	now := time.Date(2026, 7, 29, 10, 0, 0, 0, time.UTC)
	handler, err := NewRegistrationHandler(manager, NewRunStore(), RegistrationOptions{
		Now: func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("NewRegistrationHandler: %v", err)
	}

	first := registerForLifecycleTest(t, handler, reusedPath)
	firstCapture, captured := captureScopeIdentity(scopeMap, reusedCgroupID)
	if !captured {
		t.Fatal("registered cgroup did not pass the scope-map capture filter")
	}
	if _, captured := captureScopeIdentity(scopeMap, hostCgroupID); captured {
		t.Fatal("unregistered host cgroup passed the scope-map capture filter")
	}
	firstInstance, _ := strconv.ParseUint(first.InstanceID, 10, 64)
	firstCookie, _ := strconv.ParseUint(first.ScopeCookie, 10, 64)
	if firstCapture.InstanceID != firstInstance || firstCapture.ScopeCookie != firstCookie {
		t.Fatalf("first capture identity = %+v, registration = %+v", firstCapture, first)
	}
	if got := handler.AttributeEvent(firstCapture.InstanceID, firstCapture.ScopeCookie); got.Status != AttributionExact ||
		got.RunID != first.RunID || got.RunStatus != "active" {
		t.Fatalf("first active attribution = %+v", got)
	}

	if response := finishForLifecycleTest(t, handler, first.RunID); response.Code != http.StatusOK {
		t.Fatalf("finish first status = %d, body = %s", response.Code, response.Body.String())
	}
	if _, captured := captureScopeIdentity(scopeMap, reusedCgroupID); captured {
		t.Fatal("finished cgroup still passed the scope-map capture filter")
	}
	if got := handler.AttributeEvent(firstCapture.InstanceID, firstCapture.ScopeCookie); got.Status != AttributionExact ||
		got.RunID != first.RunID || got.RunStatus != "finished" {
		t.Fatalf("delayed first event attribution = %+v", got)
	}

	now = now.Add(time.Second)
	second := registerForLifecycleTest(t, handler, reusedPath)
	secondCapture, captured := captureScopeIdentity(scopeMap, reusedCgroupID)
	if !captured {
		t.Fatal("reused cgroup did not pass the scope-map capture filter")
	}
	secondCookie, _ := strconv.ParseUint(second.ScopeCookie, 10, 64)
	if secondCapture.ScopeCookie != secondCookie || secondCapture.ScopeCookie == firstCapture.ScopeCookie {
		t.Fatalf("reused capture identity = %+v, first = %+v", secondCapture, firstCapture)
	}
	if got := handler.AttributeEvent(secondCapture.InstanceID, secondCapture.ScopeCookie); got.Status != AttributionExact ||
		got.RunID != second.RunID || got.RunStatus != "active" {
		t.Fatalf("second active attribution = %+v", got)
	}
	if got := handler.AttributeEvent(firstCapture.InstanceID, firstCapture.ScopeCookie); got.Status != AttributionExact ||
		got.RunID != first.RunID {
		t.Fatalf("old event crossed into reused Run: %+v", got)
	}
	if _, captured := captureScopeIdentity(scopeMap, hostCgroupID); captured {
		t.Fatal("host cgroup passed the filter after cgroup reuse")
	}

	now = now.Add(defaultTombstoneTTL)
	if got := handler.AttributeEvent(firstCapture.InstanceID, firstCapture.ScopeCookie); got.Status != AttributionStale ||
		got.RunID != "" {
		t.Fatalf("expired first event attribution = %+v, want stale without Run", got)
	}
	if got := handler.AttributeEvent(secondCapture.InstanceID, secondCapture.ScopeCookie); got.Status != AttributionExact ||
		got.RunID != second.RunID {
		t.Fatalf("active reused Run changed after old tombstone expiry: %+v", got)
	}
}

func captureScopeIdentity(scopeMap *testScopeMap, cgroupID uint64) (scope.Value, bool) {
	value, exists := scopeMap.values[cgroupID]
	return value, exists
}
