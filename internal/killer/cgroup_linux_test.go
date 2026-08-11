//go:build linux

package killer

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

func TestRequireLeafCgroupUsesDirectoryDescriptor(t *testing.T) {
	target := t.TempDir()
	if err := os.WriteFile(filepath.Join(target, "cgroup.procs"), nil, 0o600); err != nil {
		t.Fatalf("write control file: %v", err)
	}
	fd := openTestDirectory(t, target)
	defer unix.Close(fd)

	if err := requireLeafCgroup(fd); err != nil {
		t.Fatalf("requireLeafCgroup with control file: %v", err)
	}
	if err := os.Mkdir(filepath.Join(target, "child"), 0o700); err != nil {
		t.Fatalf("create child cgroup: %v", err)
	}
	if err := requireLeafCgroup(fd); !errors.Is(err, ErrCgroupNotLeaf) {
		t.Fatalf("requireLeafCgroup error = %v, want ErrCgroupNotLeaf", err)
	}
}

func TestLinuxCgroupHandleKillWritesRelativeControl(t *testing.T) {
	target := t.TempDir()
	controlPath := filepath.Join(target, "cgroup.kill")
	if err := os.WriteFile(controlPath, nil, 0o600); err != nil {
		t.Fatalf("create cgroup.kill: %v", err)
	}
	handle := &linuxCgroupHandle{
		fd:       openTestDirectory(t, target),
		identity: CgroupIdentity{ID: 42, Path: target},
	}
	t.Cleanup(func() { _ = handle.Close() })

	if err := handle.Kill(context.Background()); err != nil {
		t.Fatalf("Kill: %v", err)
	}
	content, err := os.ReadFile(controlPath)
	if err != nil {
		t.Fatalf("read cgroup.kill: %v", err)
	}
	if string(content) != "1" {
		t.Fatalf("cgroup.kill content = %q, want 1", content)
	}
}

func TestLinuxCgroupHandleKillRechecksLeaf(t *testing.T) {
	target := t.TempDir()
	controlPath := filepath.Join(target, "cgroup.kill")
	if err := os.WriteFile(controlPath, nil, 0o600); err != nil {
		t.Fatalf("create cgroup.kill: %v", err)
	}
	if err := os.Mkdir(filepath.Join(target, "child"), 0o700); err != nil {
		t.Fatalf("create child cgroup: %v", err)
	}
	handle := &linuxCgroupHandle{
		fd:       openTestDirectory(t, target),
		identity: CgroupIdentity{ID: 42, Path: target},
	}
	t.Cleanup(func() { _ = handle.Close() })

	if err := handle.Kill(context.Background()); !errors.Is(err, ErrCgroupNotLeaf) {
		t.Fatalf("Kill error = %v, want ErrCgroupNotLeaf", err)
	}
	content, err := os.ReadFile(controlPath)
	if err != nil {
		t.Fatalf("read cgroup.kill: %v", err)
	}
	if len(content) != 0 {
		t.Fatalf("cgroup.kill was written despite child: %q", content)
	}
}

func openTestDirectory(t *testing.T, target string) int {
	t.Helper()
	fd, err := unix.Open(target, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatalf("open test directory: %v", err)
	}
	return fd
}
