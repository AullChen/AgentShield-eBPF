//go:build linux

package scope

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

// These fixtures exercise procfs and held-directory identity, not a real cgroup.
const absentRootPID = 2147483647 // Above Linux's maximum PID allocation range.

func inspectorFixture(t *testing.T, events string) *Handle {
	t.Helper()
	directory := filepath.Join(t.TempDir(), "leaf")
	if err := os.Mkdir(directory, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, "cgroup.events"), []byte(events), 0600); err != nil {
		t.Fatal(err)
	}
	fd, err := unix.Open(directory, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { unix.Close(fd) })
	return &Handle{Path: directory, fd: fd, hasFD: true, root: "/sys/fs/cgroup"}
}

func TestLinuxInspectorAcceptsExitedRootOnlyWithHeldEmptyLeaf(t *testing.T) {
	handle := inspectorFixture(t, "populated 0\nfrozen 0\n")
	state, err := (LinuxInspector{}).Inspect(handle, absentRootPID)
	if err != nil {
		t.Fatal(err)
	}
	if !state.RootExitedAndEmpty || state.RootPIDPath != "" {
		t.Fatalf("state = %+v, want exited root with empty leaf", state)
	}
	if err := os.Mkdir(filepath.Join(handle.Path, "child"), 0700); err != nil {
		t.Fatal(err)
	}
	state, err = (LinuxInspector{}).Inspect(handle, absentRootPID)
	if err != nil {
		t.Fatal(err)
	}
	if !state.RootExitedAndEmpty || len(state.ChildCgroups) != 1 || state.ChildCgroups[0] != filepath.Join(handle.Path, "child") {
		t.Fatalf("state = %+v, want child preserved for violation handling", state)
	}
}

func TestLinuxInspectorFailsClosedWithoutEmptyLeafProof(t *testing.T) {
	for _, test := range []struct {
		name    string
		events  string
		mutate  func(*Handle)
		missing bool
	}{
		{name: "remaining members", events: "populated 1\n"},
		{name: "missing populated", events: "frozen 0\n"},
		{name: "malformed populated", events: "populated 2\n"},
		{name: "contradictory populated", events: "populated 0\npopulated 1\n"},
		{name: "missing events", events: "populated 0\n", missing: true},
		{name: "no held descriptor", events: "populated 0\n", mutate: func(handle *Handle) { handle.hasFD = false }},
		{name: "no trusted mount root", events: "populated 0\n", mutate: func(handle *Handle) { handle.root = "" }},
	} {
		t.Run(test.name, func(t *testing.T) {
			handle := inspectorFixture(t, test.events)
			if test.missing {
				if err := os.Remove(filepath.Join(handle.Path, "cgroup.events")); err != nil {
					t.Fatal(err)
				}
			}
			if test.mutate != nil {
				test.mutate(handle)
			}
			if state, err := (LinuxInspector{}).Inspect(handle, absentRootPID); err == nil || state.RootExitedAndEmpty {
				t.Fatalf("Inspect() = %+v, %v; want inspection failure", state, err)
			}
		})
	}
}

func TestLinuxInspectorUsesHeldLeafAfterPathReplacement(t *testing.T) {
	for _, test := range []struct {
		name        string
		held        string
		replacement string
		empty       bool
	}{
		{name: "held leaf empty", held: "populated 0\n", replacement: "populated 1\n", empty: true},
		{name: "replacement cannot hide members", held: "populated 1\n", replacement: "populated 0\n"},
	} {
		t.Run(test.name, func(t *testing.T) {
			handle := inspectorFixture(t, test.held)
			if err := os.Rename(handle.Path, handle.Path+"-held"); err != nil {
				t.Fatal(err)
			}
			if err := os.Mkdir(handle.Path, 0700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(handle.Path, "cgroup.events"), []byte(test.replacement), 0600); err != nil {
				t.Fatal(err)
			}
			state, err := (LinuxInspector{}).Inspect(handle, absentRootPID)
			if (err == nil) != test.empty || state.RootExitedAndEmpty != test.empty {
				t.Fatalf("Inspect() = %+v, %v; want held leaf empty=%v", state, err, test.empty)
			}
		})
	}
}

func TestLinuxInspectorStillChecksLiveRootMembership(t *testing.T) {
	handle := inspectorFixture(t, "populated 0\n")
	membership, err := unifiedCgroupPath(os.Getpid())
	if err != nil {
		t.Fatal(err)
	}
	state, err := (LinuxInspector{}).Inspect(handle, os.Getpid())
	if err != nil {
		t.Fatal(err)
	}
	if want := membershipPath(handle.root, membership); state.RootExitedAndEmpty || state.RootPIDPath != want {
		t.Fatalf("state = %+v, want live root membership %q", state, want)
	}
	handle.ID = 42
	manager := newTestManager(t, &memoryMap{}, fakeResolver{handle: handle}, fakeProbe{id: 42})
	if _, err := manager.Register(context.Background(), Target{Path: handle.Path, RootPID: os.Getpid()}, Value{
		InstanceID: 1, ScopeCookie: 2,
	}); err != nil {
		t.Fatal(err)
	}
	violations, err := manager.Check(42, LinuxInspector{})
	if err != nil {
		t.Fatal(err)
	}
	if len(violations) != 1 || violations[0].Reason != ViolationMemberEscape {
		t.Fatalf("violations = %+v, want live root outside the empty leaf rejected", violations)
	}
}
