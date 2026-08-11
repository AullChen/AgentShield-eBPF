package killer

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"github.com/agentshield/agentshield-ebpf/internal/events"
	"github.com/agentshield/agentshield-ebpf/internal/scope"
)

func TestExecutorContainsOnlyRevalidatedActiveScope(t *testing.T) {
	handle := &fakeCgroupHandle{identity: CgroupIdentity{ID: 42, Path: "/agents/run-1"}}
	executor := newTestExecutor(t, &fakeScopeAuthorizer{registration: testRegistration()}, &fakeCgroupBackend{
		core: CgroupIdentity{ID: 900, Path: "/core"}, handle: handle,
	})
	event := events.KernelEvent{
		KernelMonotonicNS: 100, CgroupID: 42, InstanceID: 11, ScopeCookie: 12,
		PID: 101, TGID: 100, ActionResult: events.ActionResultNone,
	}
	original := event

	outcome, err := executor.Contain(context.Background(), Request{
		KernelMonotonicNS: event.KernelMonotonicNS,
		CgroupID:          event.CgroupID, InstanceID: event.InstanceID, ScopeCookie: event.ScopeCookie,
		PID: event.PID, TGID: event.TGID, SyscallResult: SyscallNotObserved,
	})
	if err != nil {
		t.Fatalf("Contain: %v", err)
	}
	if outcome.EnforcementMethod != MethodCgroupKill || outcome.EnforcementResult != ResultKilled ||
		outcome.SyscallResult != SyscallNotObserved || outcome.RecordType != "containment_result" {
		t.Fatalf("outcome = %+v", outcome)
	}
	if handle.kills != 1 || !handle.closed {
		t.Fatalf("handle kills/closed = %d/%t, want 1/true", handle.kills, handle.closed)
	}
	if !reflect.DeepEqual(event, original) {
		t.Fatalf("triggering event was mutated: got %+v want %+v", event, original)
	}
}

func TestExecutorRejectsReusedPIDAndCgroupIdentity(t *testing.T) {
	authorizer := &fakeScopeAuthorizer{registration: scope.Registration{
		CgroupID: 42, Path: "/agents/new-run",
		Value: scope.Value{InstanceID: 21, ScopeCookie: 22},
	}}
	backend := &fakeCgroupBackend{core: CgroupIdentity{ID: 900, Path: "/core"}}
	executor := newTestExecutor(t, authorizer, backend)

	outcome, err := executor.Contain(context.Background(), Request{
		CgroupID: 42, InstanceID: 11, ScopeCookie: 12,
		PID: 101, TGID: 100, SyscallResult: SyscallSucceeded,
	})
	if !errors.Is(err, scope.ErrScopeIdentityMismatch) {
		t.Fatalf("Contain error = %v, want ErrScopeIdentityMismatch", err)
	}
	if outcome.EnforcementResult != ResultNotAttempted || outcome.SyscallResult != SyscallSucceeded {
		t.Fatalf("outcome = %+v", outcome)
	}
	if backend.opens != 0 {
		t.Fatalf("backend opened %d targets for stale PID/scope evidence", backend.opens)
	}
}

func TestExecutorRejectsCoreCgroupAndAncestors(t *testing.T) {
	for _, test := range []struct {
		name   string
		target CgroupIdentity
		core   CgroupIdentity
	}{
		{name: "same identity", target: CgroupIdentity{ID: 50, Path: "/core"}, core: CgroupIdentity{ID: 50, Path: "/core"}},
		{name: "ancestor", target: CgroupIdentity{ID: 42, Path: "/system"}, core: CgroupIdentity{ID: 50, Path: "/system/core"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			registration := testRegistration()
			registration.CgroupID = test.target.ID
			registration.Path = test.target.Path
			backend := &fakeCgroupBackend{core: test.core}
			executor := newTestExecutor(t, &fakeScopeAuthorizer{registration: registration}, backend)
			outcome, err := executor.Contain(context.Background(), Request{
				CgroupID: test.target.ID, InstanceID: 11, ScopeCookie: 12,
				SyscallResult: SyscallNotObserved,
			})
			if !errors.Is(err, ErrProtectedTarget) {
				t.Fatalf("Contain error = %v, want ErrProtectedTarget", err)
			}
			if outcome.EnforcementResult != ResultNotAttempted || backend.opens != 0 {
				t.Fatalf("outcome/backend opens = %+v/%d", outcome, backend.opens)
			}
		})
	}
}

func TestExecutorRejectsChangedOrNonLeafCgroup(t *testing.T) {
	tests := []struct {
		name    string
		backend *fakeCgroupBackend
		want    error
	}{
		{
			name: "identity changed",
			backend: &fakeCgroupBackend{
				core:   CgroupIdentity{ID: 900, Path: "/core"},
				handle: &fakeCgroupHandle{identity: CgroupIdentity{ID: 43, Path: "/agents/run-1"}},
			},
			want: ErrCgroupIdentityMismatch,
		},
		{
			name: "child cgroup appeared",
			backend: &fakeCgroupBackend{
				core: CgroupIdentity{ID: 900, Path: "/core"}, openErr: ErrCgroupNotLeaf,
			},
			want: ErrCgroupNotLeaf,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			executor := newTestExecutor(t, &fakeScopeAuthorizer{registration: testRegistration()}, test.backend)
			outcome, err := executor.Contain(context.Background(), testRequest())
			if !errors.Is(err, test.want) {
				t.Fatalf("Contain error = %v, want %v", err, test.want)
			}
			if outcome.EnforcementResult != ResultNotAttempted {
				t.Fatalf("outcome = %+v", outcome)
			}
			if test.backend.handle != nil && test.backend.handle.kills != 0 {
				t.Fatal("changed cgroup was killed")
			}
		})
	}
}

func TestExecutorReportsContainmentFailureSeparately(t *testing.T) {
	handle := &fakeCgroupHandle{
		identity: CgroupIdentity{ID: 42, Path: "/agents/run-1"},
		killErr:  errors.New("permission denied"),
	}
	executor := newTestExecutor(t, &fakeScopeAuthorizer{registration: testRegistration()}, &fakeCgroupBackend{
		core: CgroupIdentity{ID: 900, Path: "/core"}, handle: handle,
	})
	request := testRequest()
	request.SyscallResult = SyscallFailed
	outcome, err := executor.Contain(context.Background(), request)
	if err == nil {
		t.Fatal("Contain succeeded despite cgroup.kill failure")
	}
	if outcome.EnforcementResult != ResultFailed || outcome.SyscallResult != SyscallFailed || outcome.Reason == "" {
		t.Fatalf("outcome = %+v", outcome)
	}
}

func TestExecutorReportsAuthorizedOperationalFailures(t *testing.T) {
	for _, test := range []struct {
		name    string
		backend *fakeCgroupBackend
	}{
		{
			name: "Core membership unavailable",
			backend: &fakeCgroupBackend{
				coreErr: errors.New("procfs unavailable"),
			},
		},
		{
			name: "cgroup descriptor unavailable",
			backend: &fakeCgroupBackend{
				core:    CgroupIdentity{ID: 900, Path: "/core"},
				openErr: ErrUnsupported,
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			executor := newTestExecutor(t, &fakeScopeAuthorizer{registration: testRegistration()}, test.backend)
			outcome, err := executor.Contain(context.Background(), testRequest())
			if err == nil {
				t.Fatal("Contain succeeded despite operational failure")
			}
			if outcome.EnforcementResult != ResultFailed || outcome.Reason == "" {
				t.Fatalf("outcome = %+v", outcome)
			}
		})
	}
}

func TestExecutorRechecksCoreImmediatelyBeforeKill(t *testing.T) {
	handle := &fakeCgroupHandle{identity: CgroupIdentity{ID: 42, Path: "/agents/run-1"}}
	backend := &fakeCgroupBackend{
		cores: []CgroupIdentity{
			{ID: 900, Path: "/core"},
			{ID: 42, Path: "/agents/run-1"},
		},
		handle: handle,
	}
	executor := newTestExecutor(t, &fakeScopeAuthorizer{registration: testRegistration()}, backend)

	outcome, err := executor.Contain(context.Background(), testRequest())
	if !errors.Is(err, ErrProtectedTarget) {
		t.Fatalf("Contain error = %v, want ErrProtectedTarget", err)
	}
	if outcome.EnforcementResult != ResultNotAttempted || handle.kills != 0 || !handle.closed {
		t.Fatalf("outcome/kills/closed = %+v/%d/%t", outcome, handle.kills, handle.closed)
	}
}

func TestExecutorRejectsBarePIDWithoutScopeIdentity(t *testing.T) {
	backend := &fakeCgroupBackend{core: CgroupIdentity{ID: 900, Path: "/core"}}
	executor := newTestExecutor(t, &fakeScopeAuthorizer{registration: testRegistration()}, backend)
	outcome, err := executor.Contain(context.Background(), Request{
		PID: 101, TGID: 100, SyscallResult: SyscallNotObserved,
	})
	if !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("Contain error = %v, want ErrInvalidRequest", err)
	}
	if outcome.EnforcementResult != ResultNotAttempted || backend.opens != 0 {
		t.Fatalf("outcome/backend opens = %+v/%d", outcome, backend.opens)
	}
}

func testRequest() Request {
	return Request{
		KernelMonotonicNS: 100,
		CgroupID:          42, InstanceID: 11, ScopeCookie: 12,
		PID: 101, TGID: 100, SyscallResult: SyscallNotObserved,
	}
}

func testRegistration() scope.Registration {
	return scope.Registration{
		CgroupID: 42, Path: "/agents/run-1",
		Value: scope.Value{InstanceID: 11, ScopeCookie: 12},
	}
}

func newTestExecutor(t *testing.T, scopes ScopeAuthorizer, backend CgroupBackend) *Executor {
	t.Helper()
	executor, err := NewExecutor(scopes, backend)
	if err != nil {
		t.Fatalf("NewExecutor: %v", err)
	}
	return executor
}

type fakeScopeAuthorizer struct {
	registration scope.Registration
	handle       *scope.Handle
}

func (authorizer *fakeScopeAuthorizer) WithActiveIdentity(
	cgroupID, instanceID, scopeCookie uint64,
	action func(scope.Registration, *scope.Handle) error,
) error {
	if authorizer.registration.CgroupID == 0 {
		return scope.ErrNotActive
	}
	registration := authorizer.registration
	if registration.CgroupID != cgroupID {
		return scope.ErrNotActive
	}
	if registration.Value.InstanceID != instanceID || registration.Value.ScopeCookie != scopeCookie {
		return scope.ErrScopeIdentityMismatch
	}
	trusted := authorizer.handle
	if trusted == nil {
		trusted = &scope.Handle{ID: registration.CgroupID, Path: registration.Path}
	}
	return action(registration, trusted)
}

type fakeCgroupBackend struct {
	core      CgroupIdentity
	cores     []CgroupIdentity
	coreErr   error
	handle    *fakeCgroupHandle
	openErr   error
	opens     int
	coreCalls int
}

func (backend *fakeCgroupBackend) CurrentCoreCgroup(context.Context) (CgroupIdentity, error) {
	if len(backend.cores) != 0 {
		index := backend.coreCalls
		if index >= len(backend.cores) {
			index = len(backend.cores) - 1
		}
		backend.coreCalls++
		return backend.cores[index], backend.coreErr
	}
	backend.coreCalls++
	return backend.core, backend.coreErr
}

func (backend *fakeCgroupBackend) OpenCgroup(context.Context, *scope.Handle) (CgroupHandle, error) {
	backend.opens++
	if backend.openErr != nil {
		return nil, backend.openErr
	}
	return backend.handle, nil
}

type fakeCgroupHandle struct {
	identity CgroupIdentity
	killErr  error
	kills    int
	closed   bool
}

func (handle *fakeCgroupHandle) Identity() CgroupIdentity { return handle.identity }

func (handle *fakeCgroupHandle) Kill(context.Context) error {
	handle.kills++
	return handle.killErr
}

func (handle *fakeCgroupHandle) Close() error {
	handle.closed = true
	return nil
}
