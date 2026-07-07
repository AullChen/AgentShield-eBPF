package bpfmgr

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/agentshield/agentshield-ebpf/internal/events"
)

func TestDecodeAuditEvent(t *testing.T) {
	type rawAuditEventV1 struct {
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

	raw := rawAuditEventV1{
		SchemaVersion: events.SchemaVersion,
		EventType:     events.EventTypeFileOpen,
		Action:        events.ActionAudit,
		ActionResult:  events.ActionResultAllowed,
		TimestampNS:   42,
		CgroupID:      77,
		PID:           1001,
		TGID:          1001,
		UID:           501,
		Flags:         events.FlagTruncated,
		SyscallFlags:  123,
	}
	copy(raw.Comm[:], "python")
	copy(raw.Data[:], "/etc/passwd")

	var buf bytes.Buffer
	if err := binary.Write(&buf, binary.LittleEndian, raw); err != nil {
		t.Fatalf("binary.Write: %v", err)
	}

	event, err := DecodeAuditEvent(buf.Bytes())
	if err != nil {
		t.Fatalf("DecodeAuditEvent returned error: %v", err)
	}
	if event.EventType != events.EventTypeFileOpen {
		t.Fatalf("EventType = %d, want %d", event.EventType, events.EventTypeFileOpen)
	}
	if event.PID != 1001 {
		t.Fatalf("PID = %d, want 1001", event.PID)
	}
	if event.UID != 501 {
		t.Fatalf("UID = %d, want 501", event.UID)
	}
	if event.Comm != "python" {
		t.Fatalf("Comm = %q, want python", event.Comm)
	}
	if event.Data != "/etc/passwd" {
		t.Fatalf("Data = %q, want /etc/passwd", event.Data)
	}
	if !event.Truncated {
		t.Fatal("Truncated = false, want true")
	}
}

func TestDecodeAuditEventRejectsWrongSize(t *testing.T) {
	if _, err := DecodeAuditEvent([]byte{1, 2, 3}); err == nil {
		t.Fatal("DecodeAuditEvent returned nil error for malformed sample")
	}
}
