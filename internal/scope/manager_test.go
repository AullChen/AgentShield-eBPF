package scope

import (
	"context"
	"errors"
	"io"
	"os"
	"testing"
)

type memoryMap struct {
	values  map[uint64]Value
	deleted []uint64
}

func (store *memoryMap) Put(id uint64, value Value) error {
	if store.values == nil {
		store.values = make(map[uint64]Value)
	}
	store.values[id] = value
	return nil
}

func (store *memoryMap) Delete(id uint64) error {
	delete(store.values, id)
	store.deleted = append(store.deleted, id)
	return nil
}

type fakeResolver struct {
	handle    *Handle
	err       error
	core      *Handle
	coreError error
}

func (resolver fakeResolver) ResolvePath(string) (*Handle, error) {
	return resolver.handle, resolver.err
}

func (resolver fakeResolver) ResolvePID(pid int) (*Handle, error) {
	if pid == os.Getpid() {
		if resolver.core != nil || resolver.coreError != nil {
			return resolver.core, resolver.coreError
		}
		return &Handle{ID: 999, Path: "/core/control"}, nil
	}
	return resolver.handle, resolver.err
}

type fakeProbe struct {
	id  uint64
	err error
}

func (probe fakeProbe) CurrentCgroupID(context.Context, *Handle) (uint64, error) {
	return probe.id, probe.err
}

type closeRecorder struct {
	closed bool
}

func (recorder *closeRecorder) Close() error {
	recorder.closed = true
	return nil
}

func TestManagerRegistersOnlyCrossValidatedScope(t *testing.T) {
	store := &memoryMap{}
	closer := &closeRecorder{}
	manager := newTestManager(t, store, fakeResolver{
		handle: &Handle{ID: 42, Path: "/sys/fs/cgroup/agent", closer: closer},
	}, fakeProbe{id: 42})
	value := Value{InstanceID: 11, ScopeCookie: 12, ProfileID: 13}

	registration, err := manager.Register(context.Background(), Target{
		Path:    "/sys/fs/cgroup/agent",
		RootPID: 123,
	}, value)
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	if registration.CgroupID != 42 || registration.Path != "/sys/fs/cgroup/agent" {
		t.Fatalf("registration = %+v", registration)
	}
	if got := store.values[42]; got != value {
		t.Fatalf("scope map value = %+v, want %+v", got, value)
	}
	if closer.closed {
		t.Fatal("cgroup handle closed while scope is active")
	}

	if err := manager.Unregister(42); err != nil {
		t.Fatalf("Unregister: %v", err)
	}
	if !closer.closed {
		t.Fatal("cgroup handle remained open after unregister")
	}
	if _, exists := store.values[42]; exists {
		t.Fatal("scope map entry remained after unregister")
	}
}

func TestManagerRejectsBPFIdentityMismatchWithoutWritingMap(t *testing.T) {
	store := &memoryMap{}
	closer := &closeRecorder{}
	manager := newTestManager(t, store, fakeResolver{
		handle: &Handle{ID: 42, Path: "/sys/fs/cgroup/agent", closer: closer},
	}, fakeProbe{id: 99})

	_, err := manager.Register(context.Background(), Target{Path: "/sys/fs/cgroup/agent"}, Value{
		InstanceID: 1, ScopeCookie: 2,
	})
	if !errors.Is(err, ErrIdentityMismatch) {
		t.Fatalf("Register error = %v, want ErrIdentityMismatch", err)
	}
	if len(store.values) != 0 {
		t.Fatalf("scope map was modified: %v", store.values)
	}
	if !closer.closed {
		t.Fatal("rejected cgroup handle was not closed")
	}
}

func TestManagerRejectsAmbiguousOrIncompleteTargets(t *testing.T) {
	manager := newTestManager(t, &memoryMap{}, fakeResolver{}, fakeProbe{})
	value := Value{InstanceID: 1, ScopeCookie: 2}
	for _, target := range []Target{{}, {Path: "/scope", RootPID: -1}} {
		if _, err := manager.Register(context.Background(), target, value); !errors.Is(err, ErrInvalidTarget) {
			t.Fatalf("Register(%+v) error = %v, want ErrInvalidTarget", target, err)
		}
	}
}

func TestManagerRejectsInvalidScopeValuesBeforeResolution(t *testing.T) {
	store := &memoryMap{}
	resolver := fakeResolver{handle: &Handle{ID: 42, Path: "/scope"}}
	manager := newTestManager(t, store, resolver, fakeProbe{id: 42})
	for _, value := range []Value{
		{ScopeCookie: 2},
		{InstanceID: 1},
		{InstanceID: 1, ScopeCookie: 2, Reserved: 1},
	} {
		if _, err := manager.Register(context.Background(), Target{Path: "/scope"}, value); err == nil {
			t.Fatalf("Register(%+v) returned nil error", value)
		}
	}
	if len(store.values) != 0 {
		t.Fatalf("scope map changed after invalid values: %v", store.values)
	}
}

func TestManagerRejectsDuplicateCgroup(t *testing.T) {
	store := &memoryMap{}
	resolver := fakeResolver{handle: &Handle{ID: 42, Path: "/scope", closer: io.NopCloser(nilReader{})}}
	manager := newTestManager(t, store, resolver, fakeProbe{id: 42})
	value := Value{InstanceID: 1, ScopeCookie: 2}
	if _, err := manager.Register(context.Background(), Target{Path: "/scope"}, value); err != nil {
		t.Fatalf("first Register: %v", err)
	}
	resolver.handle = &Handle{ID: 42, Path: "/scope", closer: io.NopCloser(nilReader{})}
	manager.resolver = resolver
	if _, err := manager.Register(context.Background(), Target{Path: "/scope"}, value); !errors.Is(err, ErrAlreadyActive) {
		t.Fatalf("second Register error = %v, want ErrAlreadyActive", err)
	}
}

func TestManagerRejectsOverlappingCgroupPaths(t *testing.T) {
	store := &memoryMap{}
	resolver := fakeResolver{handle: &Handle{ID: 42, Path: "/agent/leaf"}}
	manager := newTestManager(t, store, resolver, fakeProbe{id: 42})
	value := Value{InstanceID: 1, ScopeCookie: 2}
	if _, err := manager.Register(context.Background(), Target{Path: "/agent/leaf"}, value); err != nil {
		t.Fatalf("first Register: %v", err)
	}

	for _, candidate := range []struct {
		id   uint64
		path string
	}{{43, "/agent"}, {44, "/agent/leaf/child"}} {
		manager.resolver = fakeResolver{handle: &Handle{ID: candidate.id, Path: candidate.path}}
		manager.probe = fakeProbe{id: candidate.id}
		if _, err := manager.Register(context.Background(), Target{Path: candidate.path}, value); !errors.Is(err, ErrOverlap) {
			t.Fatalf("Register(%q) error = %v, want ErrOverlap", candidate.path, err)
		}
	}
	if len(store.values) != 1 {
		t.Fatalf("scope map contains %d entries, want only original binding", len(store.values))
	}
}

func TestManagerRejectsCoreCgroupAndAncestors(t *testing.T) {
	store := &memoryMap{}
	coreCloser := &closeRecorder{}
	resolver := fakeResolver{
		core:   &Handle{ID: 90, Path: "/system/core", closer: coreCloser},
		handle: &Handle{ID: 42, Path: "/system/core"},
	}
	manager := newTestManager(t, store, resolver, fakeProbe{id: 42})
	if !coreCloser.closed {
		t.Fatal("Core cgroup handle remained open after its path was recorded")
	}
	value := Value{InstanceID: 1, ScopeCookie: 2}

	for _, candidate := range []struct {
		id   uint64
		path string
	}{
		{id: 42, path: "/system/core"},
		{id: 43, path: "/system"},
		{id: 44, path: "/"},
	} {
		closer := &closeRecorder{}
		manager.resolver = fakeResolver{
			core:   &Handle{ID: 90, Path: "/system/core"},
			handle: &Handle{ID: candidate.id, Path: candidate.path, closer: closer},
		}
		manager.probe = fakeProbe{id: candidate.id}
		if _, err := manager.Register(context.Background(), Target{Path: candidate.path}, value); !errors.Is(err, ErrProtectedScope) {
			t.Fatalf("Register(%q) error = %v, want ErrProtectedScope", candidate.path, err)
		}
		if !closer.closed {
			t.Fatalf("rejected handle %q was not closed", candidate.path)
		}
	}
	if len(store.values) != 0 {
		t.Fatalf("scope map changed after protected registrations: %v", store.values)
	}
}

func TestManagerRequiresResolvableCoreCgroup(t *testing.T) {
	_, err := NewManager(&memoryMap{}, fakeResolver{
		coreError: errors.New("no self membership"),
	}, fakeProbe{})
	if err == nil {
		t.Fatal("NewManager accepted an unresolved Core cgroup")
	}
}

func TestManagerPreservesRootPIDForMigrationChecks(t *testing.T) {
	manager := newTestManager(t, &memoryMap{}, fakeResolver{
		handle: &Handle{ID: 42, Path: "/agent/leaf"},
	}, fakeProbe{id: 42})
	registration, err := manager.Register(context.Background(), Target{
		Path:    "/agent/leaf",
		RootPID: 123,
	}, Value{InstanceID: 1, ScopeCookie: 2})
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	if registration.RootPID != 123 {
		t.Fatalf("RootPID = %d, want 123", registration.RootPID)
	}
}

type nilReader struct{}

func (nilReader) Read([]byte) (int, error) { return 0, io.EOF }

func newTestManager(t *testing.T, store Map, resolver Resolver, probe Probe) *Manager {
	t.Helper()
	manager, err := NewManager(store, resolver, probe)
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	return manager
}
