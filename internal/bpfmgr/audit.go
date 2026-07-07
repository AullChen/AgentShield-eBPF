package bpfmgr

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

const (
	EventTypeFileOpen = 2
	FlagTruncated     = 1 << 0
)

var ErrUnsupported = errors.New("bpf audit is not supported on this platform")

type OpenATAuditOptions struct {
	ObjectPath string
}

type AuditEvent struct {
	SchemaVersion uint16 `json:"schema_version"`
	EventType     uint16 `json:"event_type"`
	Action        uint16 `json:"action"`
	ActionResult  uint16 `json:"action_result"`
	TimestampNS   uint64 `json:"timestamp_ns"`
	CgroupID      uint64 `json:"cgroup_id"`
	PID           uint32 `json:"pid"`
	TGID          uint32 `json:"tgid"`
	PPID          uint32 `json:"ppid"`
	UID           uint32 `json:"uid"`
	ProfileID     uint32 `json:"profile_id"`
	PolicyID      uint32 `json:"policy_id"`
	RuleID        uint32 `json:"rule_id"`
	Flags         uint32 `json:"flags"`
	SyscallFlags  uint32 `json:"syscall_flags"`
	Comm          string `json:"comm"`
	Data          string `json:"data"`
	Truncated     bool   `json:"truncated"`
}

type rawAuditEvent struct {
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

func DecodeAuditEvent(sample []byte) (AuditEvent, error) {
	var raw rawAuditEvent
	if len(sample) != binary.Size(raw) {
		return AuditEvent{}, fmt.Errorf("invalid audit event size: got %d want %d", len(sample), binary.Size(raw))
	}
	if err := binary.Read(bytes.NewReader(sample), binary.LittleEndian, &raw); err != nil {
		return AuditEvent{}, fmt.Errorf("decode audit event: %w", err)
	}

	event := AuditEvent{
		SchemaVersion: raw.SchemaVersion,
		EventType:     raw.EventType,
		Action:        raw.Action,
		ActionResult:  raw.ActionResult,
		TimestampNS:   raw.TimestampNS,
		CgroupID:      raw.CgroupID,
		PID:           raw.PID,
		TGID:          raw.TGID,
		PPID:          raw.PPID,
		UID:           raw.UID,
		ProfileID:     raw.ProfileID,
		PolicyID:      raw.PolicyID,
		RuleID:        raw.RuleID,
		Flags:         raw.Flags,
		SyscallFlags:  raw.SyscallFlags,
		Comm:          trimCString(raw.Comm[:]),
		Data:          trimCString(raw.Data[:]),
		Truncated:     raw.Flags&FlagTruncated != 0,
	}
	return event, nil
}

func trimCString(value []byte) string {
	if idx := bytes.IndexByte(value, 0); idx >= 0 {
		value = value[:idx]
	}
	return string(bytes.TrimRight(value, "\x00"))
}

func outputWriter(out io.Writer) io.Writer {
	if out == nil {
		return io.Discard
	}
	return out
}
