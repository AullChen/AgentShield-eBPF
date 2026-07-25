package scope

import (
	"fmt"
	"path"
)

const (
	ViolationChildCgroup  = "child_cgroup"
	ViolationMemberEscape = "member_escape"
)

type State struct {
	ChildCgroups []string
	RootPIDPath  string
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
	if active.registration.RootPID > 0 && path.Clean(state.RootPIDPath) != path.Clean(active.registration.Path) {
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
