package api

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/agentshield/agentshield-ebpf/internal/scope"
)

type testScopeMap struct {
	values map[uint64]scope.Value
}

func (store *testScopeMap) Put(id uint64, value scope.Value) error {
	if store.values == nil {
		store.values = make(map[uint64]scope.Value)
	}
	store.values[id] = value
	return nil
}

func (store *testScopeMap) Delete(id uint64) error {
	delete(store.values, id)
	return nil
}

type testResolver struct {
	ids map[string]uint64
}

func (resolver testResolver) ResolvePath(path string) (*scope.Handle, error) {
	return &scope.Handle{ID: resolver.ids[path], Path: path}, nil
}

func (resolver testResolver) ResolvePID(pid int) (*scope.Handle, error) {
	return &scope.Handle{ID: uint64(pid), Path: "/agent/pid-" + strconv.Itoa(pid)}, nil
}

type testProbe struct{}

func (testProbe) CurrentCgroupID(_ context.Context, handle *scope.Handle) (uint64, error) {
	return handle.ID, nil
}

func TestRegisterCreatesRunAndScopeMapEntry(t *testing.T) {
	scopeMap := &testScopeMap{}
	manager, err := scope.NewManager(scopeMap, testResolver{ids: map[string]uint64{
		"/sys/fs/cgroup/agent/leaf": 9007199254740993,
	}}, testProbe{})
	if err != nil {
		t.Fatalf("scope.NewManager: %v", err)
	}
	store := NewRunStore()
	now := time.Date(2026, 7, 23, 12, 0, 0, 0, time.UTC)
	handler, err := NewRegistrationHandler(manager, store, RegistrationOptions{
		Now: func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("NewRegistrationHandler: %v", err)
	}

	response := postJSON(t, handler.Routes(), map[string]any{
		"agent_name":   "demo-agent",
		"container_id": "container-1",
		"cgroup_path":  "/sys/fs/cgroup/agent/leaf",
		"profile_id":   7,
		"scope_mode":   "leaf_exact",
	})
	if response.Code != http.StatusCreated {
		t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
	}
	var output RegisterResponse
	if err := json.Unmarshal(response.Body.Bytes(), &output); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if output.CgroupID != "9007199254740993" || output.InstanceID == "0" || output.ScopeCookie == "0" {
		t.Fatalf("response identities = %+v", output)
	}
	cgroupID, _ := strconv.ParseUint(output.CgroupID, 10, 64)
	value, exists := scopeMap.values[cgroupID]
	if !exists {
		t.Fatal("scope map entry does not exist after registration")
	}
	if strconv.FormatUint(value.InstanceID, 10) != output.InstanceID ||
		strconv.FormatUint(value.ScopeCookie, 10) != output.ScopeCookie ||
		value.ProfileID != 7 {
		t.Fatalf("scope map value = %+v, response = %+v", value, output)
	}

	run, exists := store.Get(output.RunID)
	if !exists || store.Len() != 1 {
		t.Fatalf("stored run exists=%v count=%d", exists, store.Len())
	}
	if got := sha256.Sum256([]byte(output.IngestToken)); got != run.TokenHash {
		t.Fatal("stored token hash does not match returned token")
	}
	if output.IngestToken == "" || string(run.TokenHash[:]) == output.IngestToken {
		t.Fatal("plaintext token was not returned once and stored only as a hash")
	}
	verified, err := handler.VerifyIngestToken(output.IngestToken)
	if err != nil || verified.RunID != output.RunID {
		t.Fatalf("VerifyIngestToken = %q, %v", verified.RunID, err)
	}
}

func TestRegisterRejectsAgentSuppliedCgroupIdentity(t *testing.T) {
	scopeMap := &testScopeMap{}
	manager, err := scope.NewManager(scopeMap, testResolver{}, testProbe{})
	if err != nil {
		t.Fatalf("scope.NewManager: %v", err)
	}
	handler, err := NewRegistrationHandler(manager, NewRunStore(), RegistrationOptions{})
	if err != nil {
		t.Fatalf("NewRegistrationHandler: %v", err)
	}

	response := postJSON(t, handler, map[string]any{
		"agent_name":  "untrusted-agent",
		"cgroup_path": "/sys/fs/cgroup/host",
		"cgroup_id":   "1",
		"run_id":      "chosen-by-agent",
	})
	if response.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", response.Code)
	}
	if len(scopeMap.values) != 0 {
		t.Fatalf("scope map changed after rejected request: %v", scopeMap.values)
	}
}

func TestRegisterRejectsOverlappingActiveBinding(t *testing.T) {
	scopeMap := &testScopeMap{}
	manager, err := scope.NewManager(scopeMap, testResolver{ids: map[string]uint64{
		"/agent/leaf":       11,
		"/agent/leaf/child": 12,
	}}, testProbe{})
	if err != nil {
		t.Fatalf("scope.NewManager: %v", err)
	}
	handler, err := NewRegistrationHandler(manager, NewRunStore(), RegistrationOptions{})
	if err != nil {
		t.Fatalf("NewRegistrationHandler: %v", err)
	}

	first := postJSON(t, handler, map[string]any{"agent_name": "first", "cgroup_path": "/agent/leaf"})
	if first.Code != http.StatusCreated {
		t.Fatalf("first status = %d, body = %s", first.Code, first.Body.String())
	}
	second := postJSON(t, handler, map[string]any{"agent_name": "second", "cgroup_path": "/agent/leaf/child"})
	if second.Code != http.StatusConflict {
		t.Fatalf("second status = %d, body = %s", second.Code, second.Body.String())
	}
	if len(scopeMap.values) != 1 {
		t.Fatalf("scope map entries = %d, want 1", len(scopeMap.values))
	}
}

func TestVerifyIngestTokenRejectsTamperingAndExpiry(t *testing.T) {
	scopeMap := &testScopeMap{}
	manager, _ := scope.NewManager(scopeMap, testResolver{ids: map[string]uint64{"/agent": 1}}, testProbe{})
	now := time.Date(2026, 7, 23, 12, 0, 0, 0, time.UTC)
	handler, err := NewRegistrationHandler(manager, NewRunStore(), RegistrationOptions{
		Now:      func() time.Time { return now },
		TokenTTL: time.Minute,
	})
	if err != nil {
		t.Fatalf("NewRegistrationHandler: %v", err)
	}
	response := postJSON(t, handler, map[string]any{"agent_name": "agent", "cgroup_path": "/agent"})
	var output RegisterResponse
	_ = json.Unmarshal(response.Body.Bytes(), &output)

	if _, err := handler.VerifyIngestToken(output.IngestToken + "x"); err == nil {
		t.Fatal("tampered token was accepted")
	}
	handler.now = func() time.Time { return now.Add(2 * time.Minute) }
	if _, err := handler.VerifyIngestToken(output.IngestToken); err == nil {
		t.Fatal("expired token was accepted")
	}
}

func TestVerifyIngestTokenHonorsSubsecondExpiry(t *testing.T) {
	scopeMap := &testScopeMap{}
	manager, _ := scope.NewManager(scopeMap, testResolver{ids: map[string]uint64{"/agent": 1}}, testProbe{})
	now := time.Date(2026, 7, 25, 12, 0, 0, 900_000_000, time.UTC)
	handler, err := NewRegistrationHandler(manager, NewRunStore(), RegistrationOptions{
		Now:      func() time.Time { return now },
		TokenTTL: time.Second,
	})
	if err != nil {
		t.Fatalf("NewRegistrationHandler: %v", err)
	}
	response := postJSON(t, handler, map[string]any{"agent_name": "agent", "cgroup_path": "/agent"})
	var output RegisterResponse
	if err := json.Unmarshal(response.Body.Bytes(), &output); err != nil {
		t.Fatalf("decode response: %v", err)
	}

	handler.now = func() time.Time { return now.Add(500 * time.Millisecond) }
	if _, err := handler.VerifyIngestToken(output.IngestToken); err != nil {
		t.Fatalf("token expired before advertised subsecond deadline: %v", err)
	}
	handler.now = func() time.Time { return now.Add(time.Second) }
	if _, err := handler.VerifyIngestToken(output.IngestToken); err == nil {
		t.Fatal("token remained valid at its advertised deadline")
	}
}

func TestVerifyIngestTokenRejectsFailedRun(t *testing.T) {
	scopeMap := &testScopeMap{}
	manager, _ := scope.NewManager(scopeMap, testResolver{ids: map[string]uint64{"/agent": 1}}, testProbe{})
	store := NewRunStore()
	now := time.Date(2026, 7, 25, 12, 0, 0, 0, time.UTC)
	handler, err := NewRegistrationHandler(manager, store, RegistrationOptions{
		Now: func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("NewRegistrationHandler: %v", err)
	}
	response := postJSON(t, handler, map[string]any{"agent_name": "agent", "cgroup_path": "/agent"})
	var output RegisterResponse
	if err := json.Unmarshal(response.Body.Bytes(), &output); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if _, transitioned, exists := store.FailScope(1, scope.ViolationMemberEscape); !exists || !transitioned {
		t.Fatal("registered Run was not found by cgroup ID")
	}

	if _, err := handler.VerifyIngestToken(output.IngestToken); err == nil {
		t.Fatal("failed Run retained ingest access")
	}
}

func postJSON(t *testing.T, handler http.Handler, input any) *httptest.ResponseRecorder {
	t.Helper()
	payload, err := json.Marshal(input)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	request := httptest.NewRequest(http.MethodPost, RegisterPath, bytes.NewReader(payload))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	return response
}
