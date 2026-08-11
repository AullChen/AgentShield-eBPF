//go:build linux

package scope

import (
	"testing"

	"golang.org/x/sys/unix"
)

func TestHandleDuplicateFDPreservesIdentityAndCloseOnExec(t *testing.T) {
	fd, err := unix.Open(t.TempDir(), unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatalf("open directory: %v", err)
	}
	defer unix.Close(fd)
	handle := &Handle{fd: fd, hasFD: true}

	duplicate, err := handle.DuplicateFD()
	if err != nil {
		t.Fatalf("DuplicateFD: %v", err)
	}
	defer unix.Close(duplicate)
	flags, err := unix.FcntlInt(uintptr(duplicate), unix.F_GETFD, 0)
	if err != nil {
		t.Fatalf("read descriptor flags: %v", err)
	}
	if flags&unix.FD_CLOEXEC == 0 {
		t.Fatal("duplicate descriptor is missing FD_CLOEXEC")
	}
	var originalStat, duplicateStat unix.Stat_t
	if err := unix.Fstat(fd, &originalStat); err != nil {
		t.Fatalf("stat original descriptor: %v", err)
	}
	if err := unix.Fstat(duplicate, &duplicateStat); err != nil {
		t.Fatalf("stat duplicate descriptor: %v", err)
	}
	if originalStat.Dev != duplicateStat.Dev || originalStat.Ino != duplicateStat.Ino {
		t.Fatalf("duplicate identity = %d/%d, want %d/%d",
			duplicateStat.Dev, duplicateStat.Ino, originalStat.Dev, originalStat.Ino)
	}
}
