//go:build linux

package scope

import (
	"fmt"

	"golang.org/x/sys/unix"
)

// DuplicateFD returns a close-on-exec duplicate of the trusted cgroup
// directory descriptor. The caller owns the duplicate and must close it.
func (handle *Handle) DuplicateFD() (int, error) {
	if handle == nil || !handle.hasFD || handle.fd < 0 {
		return -1, ErrHandleUnavailable
	}
	duplicate, err := unix.FcntlInt(uintptr(handle.fd), unix.F_DUPFD_CLOEXEC, 0)
	if err != nil {
		return -1, fmt.Errorf("duplicate cgroup directory descriptor: %w", err)
	}
	return duplicate, nil
}
