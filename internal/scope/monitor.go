package scope

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"strings"
	"syscall"
)

const (
	ViolationChildCgroup      = "child_cgroup"
	ViolationMemberEscape     = "member_escape"
	ViolationInspectionFailed = "inspection_failed"
)

type State struct {
	ChildCgroups []string
	RootPIDPath  string
	// RootExitedAndEmpty requires a missing root PID and populated 0 from the held leaf.
	// It permits waiting for trusted finish, not finishing or unregistering the Run.
	RootExitedAndEmpty bool
}

type Inspector interface {
	Inspect(*Handle, int) (State, error)
}

type Violation struct {
	EventType string `json:"event_type"`
	CgroupID  uint64 `json:"cgroup_id,string"`
	Path      string `json:"cgroup_path"`
	Reason    string `json:"reason"`
	Detail    string `json:"detail"`
}

func (manager *Manager) Check(cgroupID uint64, inspector Inspector) ([]Violation, error) {
	if inspector == nil {
		return nil, fmt.Errorf("scope inspector is required")
	}
	manager.mu.Lock()
	defer manager.mu.Unlock()
	active, exists := manager.active[cgroupID]
	if !exists {
		return nil, fmt.Errorf("%w: %d", ErrNotActive, cgroupID)
	}

	state, err := inspector.Inspect(active.handle, active.registration.RootPID)
	if err != nil {
		return nil, fmt.Errorf("inspect active cgroup %d: %w", cgroupID, err)
	}
	violations := make([]Violation, 0, len(state.ChildCgroups)+1)
	for _, child := range state.ChildCgroups {
		violations = append(violations, Violation{
			EventType: "scope_violation",
			CgroupID:  cgroupID,
			Path:      active.registration.Path,
			Reason:    ViolationChildCgroup,
			Detail:    child,
		})
	}
	if active.registration.RootPID > 0 && !state.RootExitedAndEmpty && path.Clean(state.RootPIDPath) != path.Clean(active.registration.Path) {
		violations = append(violations, Violation{
			EventType: "scope_violation",
			CgroupID:  cgroupID,
			Path:      active.registration.Path,
			Reason:    ViolationMemberEscape,
			Detail:    state.RootPIDPath,
		})
	}
	return violations, nil
}

func membershipPath(root, membership string) string {
	return path.Join(path.Clean(root), path.Clean("/"+membership))
}

func rootPIDExited(err error) bool {
	// procfs can return ESRCH if the task is reaped between open and read.
	return errors.Is(err, os.ErrNotExist) || errors.Is(err, syscall.ESRCH)
}

func cgroupUnpopulated(events io.Reader) (bool, error) {
	scanner := bufio.NewScanner(events)
	found, empty := false, false
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) == 0 || fields[0] != "populated" {
			continue
		}
		if found || len(fields) != 2 || (fields[1] != "0" && fields[1] != "1") {
			return false, fmt.Errorf("invalid populated field in cgroup.events")
		}
		found, empty = true, fields[1] == "0"
	}
	if err := scanner.Err(); err != nil {
		return false, fmt.Errorf("read cgroup.events: %w", err)
	}
	if !found {
		return false, fmt.Errorf("cgroup.events has no populated field")
	}
	return empty, nil
}
