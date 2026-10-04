//go:build linux

package api

import (
	"os"
	"path/filepath"
	"testing"
)

func TestWorkloadUnixPermissions(t *testing.T) {
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "workload.sock")
	listener, err := ListenWorkloadUnix(path)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0o666 {
		t.Fatal("workload socket is not bind-mount accessible")
	}
	if err := os.Chmod(directory, 0o750); err != nil {
		t.Fatal(err)
	}
	if leaked, err := ListenWorkloadUnix(filepath.Join(directory, "rejected.sock")); err == nil {
		leaked.Close()
		t.Fatal("accepted searchable parent")
	}
}
