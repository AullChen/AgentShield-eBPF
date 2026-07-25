package scope

import (
	"context"
	"testing"
)

type staticInspector struct {
	state State
	err   error
}

func (inspector staticInspector) Inspect(*Handle, int) (State, error) {
	return inspector.state, inspector.err
}

func TestCheckReportsChildCgroupAndMemberEscape(t *testing.T) {
	store := &memoryMap{}
	manager := newTestManager(t, store, fakeResolver{
		handle: &Handle{ID: 42, Path: "/sys/fs/cgroup/agent/leaf"},
	}, fakeProbe{id: 42})
	if _, err := manager.Register(context.Background(), Target{PID: 100}, Value{
		InstanceID: 1, ScopeCookie: 2,
	}); err != nil {
		t.Fatalf("Register: %v", err)
	}

	violations, err := manager.Check(42, staticInspector{state: State{
		ChildCgroups: []string{"/sys/fs/cgroup/agent/leaf/child"},
		RootPIDPath:  "/sys/fs/cgroup/escaped",
	}})
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if len(violations) != 2 {
		t.Fatalf("violations = %+v, want child and escape", violations)
	}
	if violations[0].EventType != "scope_violation" || violations[0].Reason != ViolationChildCgroup {
		t.Fatalf("child violation = %+v", violations[0])
	}
	if violations[1].EventType != "scope_violation" || violations[1].Reason != ViolationMemberEscape {
		t.Fatalf("escape violation = %+v", violations[1])
	}
}

func TestCheckAcceptsUnchangedExactLeaf(t *testing.T) {
	store := &memoryMap{}
	manager := newTestManager(t, store, fakeResolver{
		handle: &Handle{ID: 42, Path: "/sys/fs/cgroup/agent/leaf"},
	}, fakeProbe{id: 42})
	if _, err := manager.Register(context.Background(), Target{PID: 100}, Value{
		InstanceID: 1, ScopeCookie: 2,
	}); err != nil {
		t.Fatalf("Register: %v", err)
	}
	violations, err := manager.Check(42, staticInspector{state: State{
		RootPIDPath: "/sys/fs/cgroup/agent/leaf",
	}})
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if len(violations) != 0 {
		t.Fatalf("violations = %+v, want none", violations)
	}
	if _, hostCaptured := manager.Lookup(99); hostCaptured {
		t.Fatal("unregistered host cgroup was considered captured")
	}
}

func TestMembershipPathUsesResolverMountRoot(t *testing.T) {
	if got, want := membershipPath("/mnt/private-cgroup2", "/agent/leaf"), "/mnt/private-cgroup2/agent/leaf"; got != want {
		t.Fatalf("membershipPath() = %q, want %q", got, want)
	}
}
