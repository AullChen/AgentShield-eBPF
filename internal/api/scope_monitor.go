package api

import (
	"fmt"
	"strconv"
	"time"

	"github.com/agentshield/agentshield-ebpf/internal/scope"
)

type ScopeViolationEvent struct {
	EventType   string `json:"event_type"`
	RunID       string `json:"run_id"`
	CgroupID    string `json:"cgroup_id"`
	InstanceID  string `json:"instance_id"`
	ScopeCookie string `json:"scope_cookie"`
	Reason      string `json:"reason"`
	Detail      string `json:"detail"`
	ObservedAt  string `json:"observed_at"`
}

func MonitorScopesOnce(manager *scope.Manager, inspector scope.Inspector, store *RunStore, now time.Time, emit func(ScopeViolationEvent) error) error {
	if manager == nil || inspector == nil || store == nil || emit == nil {
		return fmt.Errorf("scope manager, inspector, run store, and emitter are required")
	}
	for _, cgroupID := range manager.ActiveIDs() {
		violations, err := manager.Check(cgroupID, inspector)
		if err != nil {
			return err
		}
		for _, violation := range violations {
			run, exists := store.FailScope(cgroupID, violation.Reason)
			if !exists {
				return fmt.Errorf("active cgroup %d has no Agent Run", cgroupID)
			}
			event := ScopeViolationEvent{
				EventType:   "scope_violation",
				RunID:       run.RunID,
				CgroupID:    strconv.FormatUint(cgroupID, 10),
				InstanceID:  strconv.FormatUint(run.InstanceID, 10),
				ScopeCookie: strconv.FormatUint(run.ScopeCookie, 10),
				Reason:      violation.Reason,
				Detail:      violation.Detail,
				ObservedAt:  now.UTC().Format(time.RFC3339Nano),
			}
			if err := emit(event); err != nil {
				return fmt.Errorf("emit scope violation: %w", err)
			}
		}
	}
	return nil
}
