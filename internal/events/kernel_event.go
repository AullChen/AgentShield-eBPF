package events

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

const (
	SchemaVersion uint16 = 1

	EventTypeUnspecified uint16 = 0
	EventTypeExecAttempt uint16 = 1
	EventTypeFileOpen    uint16 = 2
	EventTypeNetConnect  uint16 = 3
	EventTypePolicyHit   uint16 = 4
	EventTypeBlockResult uint16 = 5
	EventTypeDropNotice  uint16 = 6
	EventTypeSelfDiag    uint16 = 7

	ActionAudit uint16 = 0
	ActionAlert uint16 = 1
	ActionBlock uint16 = 2
	ActionKill  uint16 = 3

	ActionResultNone     uint16 = 0
	ActionResultAllowed  uint16 = 1
	ActionResultBlocked  uint16 = 2
	ActionResultKilled   uint16 = 3
	ActionResultFailed   uint16 = 4
	ActionResultFallback uint16 = 5

	FlagTruncated uint32 = 1 << 0
	FlagFallback  uint32 = 1 << 1
)

type KernelEvent struct {
	SchemaVersion    uint16 `json:"schema_version"`
	EventType        uint16 `json:"event_type"`
	EventTypeName    string `json:"event_type_name"`
	Action           uint16 `json:"action"`
	ActionName       string `json:"action_name"`
	ActionResult     uint16 `json:"action_result"`
	ActionResultName string `json:"action_result_name"`
	TimestampNS      uint64 `json:"timestamp_ns"`
	CgroupID         uint64 `json:"cgroup_id"`
	PID              uint32 `json:"pid"`
	TGID             uint32 `json:"tgid"`
	PPID             uint32 `json:"ppid"`
	UID              uint32 `json:"uid"`
	ProfileID        uint32 `json:"profile_id"`
	PolicyID         uint32 `json:"policy_id"`
	RuleID           uint32 `json:"rule_id"`
	Flags            uint32 `json:"flags"`
	SyscallFlags     uint32 `json:"syscall_flags"`
	Comm             string `json:"comm"`
	Data             string `json:"data"`
	Truncated        bool   `json:"truncated"`
}

type rawKernelEventV1 struct {
	SchemaVersion uint16
	EventType     uint16
	Action        uint16
	ActionResult  uint16
	TimestampNS   uint64
	CgroupID      uint64
	PID           uint32
	TGID          uint32
	PPID          uint32
	UID           uint32
	ProfileID     uint32
	PolicyID      uint32
	RuleID        uint32
	Flags         uint32
	SyscallFlags  uint32
	Reserved      uint32
	Comm          [16]byte
	Data          [256]byte
}

func KernelEventV1Size() int {
	return binary.Size(rawKernelEventV1{})
}

func DecodeKernelEvent(sample []byte) (KernelEvent, error) {
	var raw rawKernelEventV1
	if len(sample) != KernelEventV1Size() {
		return KernelEvent{}, fmt.Errorf("invalid kernel event size: got %d want %d", len(sample), KernelEventV1Size())
	}
	if err := binary.Read(bytes.NewReader(sample), binary.LittleEndian, &raw); err != nil {
		return KernelEvent{}, fmt.Errorf("decode kernel event: %w", err)
	}
	if raw.SchemaVersion != SchemaVersion {
		return KernelEvent{}, fmt.Errorf("unsupported kernel event schema version: got %d want %d", raw.SchemaVersion, SchemaVersion)
	}

	return KernelEvent{
		SchemaVersion:    raw.SchemaVersion,
		EventType:        raw.EventType,
		EventTypeName:    EventTypeName(raw.EventType),
		Action:           raw.Action,
		ActionName:       ActionName(raw.Action),
		ActionResult:     raw.ActionResult,
		ActionResultName: ActionResultName(raw.ActionResult),
		TimestampNS:      raw.TimestampNS,
		CgroupID:         raw.CgroupID,
		PID:              raw.PID,
		TGID:             raw.TGID,
		PPID:             raw.PPID,
		UID:              raw.UID,
		ProfileID:        raw.ProfileID,
		PolicyID:         raw.PolicyID,
		RuleID:           raw.RuleID,
		Flags:            raw.Flags,
		SyscallFlags:     raw.SyscallFlags,
		Comm:             CleanCString(raw.Comm[:]),
		Data:             CleanCString(raw.Data[:]),
		Truncated:        raw.Flags&FlagTruncated != 0,
	}, nil
}

func CleanCString(value []byte) string {
	if idx := bytes.IndexByte(value, 0); idx >= 0 {
		value = value[:idx]
	}
	return string(bytes.TrimRight(value, "\x00"))
}

func EventTypeName(eventType uint16) string {
	switch eventType {
	case EventTypeExecAttempt:
		return "exec_attempt"
	case EventTypeFileOpen:
		return "file_open"
	case EventTypeNetConnect:
		return "net_connect"
	case EventTypePolicyHit:
		return "policy_hit"
	case EventTypeBlockResult:
		return "block_result"
	case EventTypeDropNotice:
		return "drop_notice"
	case EventTypeSelfDiag:
		return "self_diag"
	case EventTypeUnspecified:
		return "unspecified"
	default:
		return "unknown"
	}
}

func ActionName(action uint16) string {
	switch action {
	case ActionAudit:
		return "audit"
	case ActionAlert:
		return "alert"
	case ActionBlock:
		return "block"
	case ActionKill:
		return "kill"
	default:
		return "unknown"
	}
}

func ActionResultName(result uint16) string {
	switch result {
	case ActionResultNone:
		return "none"
	case ActionResultAllowed:
		return "allowed"
	case ActionResultBlocked:
		return "blocked"
	case ActionResultKilled:
		return "killed"
	case ActionResultFailed:
		return "failed"
	case ActionResultFallback:
		return "fallback"
	default:
		return "unknown"
	}
}
