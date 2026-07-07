package events

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func TestDecodeKernelEventV1(t *testing.T) {
	raw := rawKernelEventV1{
		SchemaVersion: SchemaVersion,
		EventType:     EventTypeFileOpen,
		Action:        ActionAudit,
		ActionResult:  ActionResultAllowed,
		TimestampNS:   42,
		CgroupID:      77,
		PID:           1001,
		TGID:          1001,
		UID:           501,
		Flags:         FlagTruncated,
		SyscallFlags:  123,
	}
	copy(raw.Comm[:], "python")
	copy(raw.Data[:], "/etc/passwd")

	event := decodeRawForTest(t, raw)
	if event.SchemaVersion != SchemaVersion {
		t.Fatalf("SchemaVersion = %d, want %d", event.SchemaVersion, SchemaVersion)
	}
	if event.EventType != EventTypeFileOpen || event.EventTypeName != "file_open" {
		t.Fatalf("event type = %d/%q", event.EventType, event.EventTypeName)
	}
	if event.ActionName != "audit" {
		t.Fatalf("ActionName = %q, want audit", event.ActionName)
	}
	if event.ActionResultName != "allowed" {
		t.Fatalf("ActionResultName = %q, want allowed", event.ActionResultName)
	}
	if event.TimestampNS != 42 {
		t.Fatalf("TimestampNS = %d, want 42", event.TimestampNS)
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

func TestDecodeKernelEventRejectsWrongSize(t *testing.T) {
	if _, err := DecodeKernelEvent([]byte{1, 2, 3}); err == nil {
		t.Fatal("DecodeKernelEvent returned nil error for malformed sample")
	}
}

func TestDecodeKernelEventRejectsUnsupportedSchema(t *testing.T) {
	raw := rawKernelEventV1{SchemaVersion: SchemaVersion + 1}
	var buf bytes.Buffer
	if err := binary.Write(&buf, binary.LittleEndian, raw); err != nil {
		t.Fatalf("binary.Write: %v", err)
	}

	if _, err := DecodeKernelEvent(buf.Bytes()); err == nil {
		t.Fatal("DecodeKernelEvent returned nil error for unsupported schema")
	}
}

func TestCleanCString(t *testing.T) {
	tests := []struct {
		name string
		in   []byte
		want string
	}{
		{name: "nul terminated", in: []byte{'a', 'b', 0, 'c'}, want: "ab"},
		{name: "full buffer no nul", in: []byte{'a', 'b', 'c'}, want: "abc"},
		{name: "all zeros", in: []byte{0, 0, 0}, want: ""},
		{name: "right padded zeros", in: []byte{'x', 'y', 0, 0}, want: "xy"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := CleanCString(test.in); got != test.want {
				t.Fatalf("CleanCString(%v) = %q, want %q", test.in, got, test.want)
			}
		})
	}
}

func TestNameFallbacks(t *testing.T) {
	if EventTypeName(999) != "unknown" {
		t.Fatal("unknown event type did not map to unknown")
	}
	if ActionName(999) != "unknown" {
		t.Fatal("unknown action did not map to unknown")
	}
	if ActionResultName(999) != "unknown" {
		t.Fatal("unknown action result did not map to unknown")
	}
}

func decodeRawForTest(t *testing.T, raw rawKernelEventV1) KernelEvent {
	t.Helper()

	var buf bytes.Buffer
	if err := binary.Write(&buf, binary.LittleEndian, raw); err != nil {
		t.Fatalf("binary.Write: %v", err)
	}

	event, err := DecodeKernelEvent(buf.Bytes())
	if err != nil {
		t.Fatalf("DecodeKernelEvent returned error: %v", err)
	}
	return event
}
