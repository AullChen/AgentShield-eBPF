package scope

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"syscall"
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
	if _, err := manager.Register(context.Background(), Target{
		Path:    "/sys/fs/cgroup/agent/leaf",
		RootPID: 100,
	}, Value{
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
	if _, err := manager.Register(context.Background(), Target{
		Path:    "/sys/fs/cgroup/agent/leaf",
		RootPID: 100,
	}, Value{
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

func TestCheckStillRejectsChildCgroupsAfterRootExit(t *testing.T) {
	manager := newTestManager(t, &memoryMap{}, fakeResolver{
		handle: &Handle{ID: 42, Path: "/agent/leaf"},
	}, fakeProbe{id: 42})
	if _, err := manager.Register(context.Background(), Target{Path: "/agent/leaf", RootPID: 100}, Value{
		InstanceID: 1, ScopeCookie: 2,
	}); err != nil {
		t.Fatal(err)
	}
	violations, err := manager.Check(42, staticInspector{state: State{
		ChildCgroups: []string{"/agent/leaf/child"}, RootExitedAndEmpty: true,
	}})
	if err != nil {
		t.Fatal(err)
	}
	if len(violations) != 1 || violations[0].Reason != ViolationChildCgroup {
		t.Fatalf("violations = %+v, want child cgroup violation", violations)
	}
	inspectionErr := errors.New("inspection failed")
	if _, err := manager.Check(42, staticInspector{
		state: State{RootExitedAndEmpty: true}, err: inspectionErr,
	}); !errors.Is(err, inspectionErr) {
		t.Fatalf("inspection error = %v, want %v", err, inspectionErr)
	}
}

func TestCgroupUnpopulatedRequiresValidKernelState(t *testing.T) {
	for _, test := range []struct {
		name   string
		events string
		empty  bool
		bad    bool
	}{
		{name: "empty", events: "populated 0\nfrozen 0\n", empty: true},
		{name: "remaining members", events: "populated 1\nfrozen 0\n"},
		{name: "future fields", events: "future_field 2\npopulated 0\n", empty: true},
		{name: "missing", events: "frozen 0\n", bad: true},
		{name: "invalid value", events: "populated 2\n", bad: true},
		{name: "missing value", events: "populated\n", bad: true},
		{name: "extra value", events: "populated 0 1\n", bad: true},
		{name: "duplicate", events: "populated 0\npopulated 0\n", bad: true},
		{name: "contradictory", events: "populated 0\npopulated 1\n", bad: true},
		{name: "read failure", events: "populated 0\n" + strings.Repeat("x", 70_000), bad: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			empty, err := cgroupUnpopulated(strings.NewReader(test.events))
			if (err != nil) != test.bad || empty != test.empty {
				t.Fatalf("cgroupUnpopulated() = %v, %v; want empty=%v, error=%v", empty, err, test.empty, test.bad)
			}
		})
	}
}

func TestRootPIDExitedOnlyAcceptsProcessDisappearance(t *testing.T) {
	for _, test := range []struct {
		name string
		err  error
		gone bool
	}{
		{name: "missing proc entry", err: os.ErrNotExist, gone: true},
		{name: "reaped during read", err: syscall.ESRCH, gone: true},
		{name: "success"},
		{name: "permission denied", err: os.ErrPermission},
		{name: "truncated membership", err: io.EOF},
		{name: "other inspection error", err: errors.New("no unified membership")},
	} {
		t.Run(test.name, func(t *testing.T) {
			for _, err := range []error{test.err, fmt.Errorf("read PID cgroup membership: %w", test.err)} {
				if gone := rootPIDExited(err); gone != test.gone {
					t.Fatalf("rootPIDExited(%v) = %v, want %v", err, gone, test.gone)
				}
			}
		})
	}
}
