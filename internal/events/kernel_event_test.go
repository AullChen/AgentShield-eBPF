package events

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"testing"
	"unsafe"
)

func TestKernelEventV2WireSize(t *testing.T) {
	const want = 336
	if got := KernelEventV2Size(); got != want {
		t.Fatalf("KernelEventV2Size() = %d, want %d", got, want)
	}
	var raw rawKernelEventV2
	if got, want := unsafe.Offsetof(raw.CapturedArgcPlusOne), uintptr(60); got != want {
		t.Fatalf("CapturedArgcPlusOne offset = %d, want %d", got, want)
	}
	if got, want := unsafe.Offsetof(raw.Data), uintptr(80); got != want {
		t.Fatalf("Data offset = %d, want %d", got, want)
	}
}

func TestKernelEventJSONPreservesUint64Precision(t *testing.T) {
	event := KernelEvent{
		JSONSchemaVersion: JSONSchemaVersion,
		SchemaVersion:     WireSchemaVersion,
		TimestampNS:       9_007_199_254_740_993,
		CgroupID:          18_446_744_073_709_551_615,
	}

	payload, err := json.Marshal(event)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(payload, &decoded); err != nil {
		t.Fatalf("json.Unmarshal: %v", err)
	}
	if got := decoded["timestamp_ns"]; got != "9007199254740993" {
		t.Fatalf("timestamp_ns = %#v, want exact decimal string", got)
	}
	if got := decoded["cgroup_id"]; got != "18446744073709551615" {
		t.Fatalf("cgroup_id = %#v, want exact decimal string", got)
	}
	if got := decoded["schema_version"]; got != float64(JSONSchemaVersion) {
		t.Fatalf("schema_version = %#v, want JSON schema %d", got, JSONSchemaVersion)
	}
	if got := decoded["wire_schema_version"]; got != float64(WireSchemaVersion) {
		t.Fatalf("wire_schema_version = %#v, want wire schema %d", got, WireSchemaVersion)
	}
}

func TestDecodeKernelEventV2(t *testing.T) {
	raw := rawKernelEventV2{
		SchemaVersion: SchemaVersion,
		EventType:     EventTypeFileOpen,
		Action:        ActionAudit,
		ActionResult:  ActionResultNone,
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
	if event.ActionResultName != "none" {
		t.Fatalf("ActionResultName = %q, want none", event.ActionResultName)
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

func TestDecodeKernelExecEventV2(t *testing.T) {
	raw := rawKernelEventV2{
		SchemaVersion:       SchemaVersion,
		EventType:           EventTypeExecAttempt,
		Action:              ActionAudit,
		ActionResult:        ActionResultNone,
		PID:                 1001,
		PPID:                999,
		CapturedArgcPlusOne: 4,
	}
	copy(raw.Comm[:], "bash")
	copy(raw.Data[:execExecutableLength], "/usr/bin/bash")
	copy(raw.Data[execExecutableLength:], "bash")
	copy(raw.Data[execExecutableLength+execArgumentLength:], "-c")
	copy(raw.Data[execExecutableLength+2*execArgumentLength:], "echo ok")

	event := decodeRawForTest(t, raw)
	if event.EventTypeName != "exec_attempt" {
		t.Fatalf("EventTypeName = %q, want exec_attempt", event.EventTypeName)
	}
	if event.Data != "/usr/bin/bash" {
		t.Fatalf("Data = %q, want /usr/bin/bash", event.Data)
	}
	if event.PPID != 999 {
		t.Fatalf("PPID = %d, want 999", event.PPID)
	}
	wantArgv := []string{"bash", "-c", "echo ok"}
	if len(event.Argv) != len(wantArgv) {
		t.Fatalf("Argv = %v, want %v", event.Argv, wantArgv)
	}
	for i := range wantArgv {
		if event.Argv[i] != wantArgv[i] {
			t.Fatalf("Argv[%d] = %q, want %q", i, event.Argv[i], wantArgv[i])
		}
	}
	if event.CapturedArgc != uint32(len(wantArgv)) {
		t.Fatalf("CapturedArgc = %d, want %d", event.CapturedArgc, len(wantArgv))
	}
}

func TestDecodeKernelExecEventPreservesEmptyArgument(t *testing.T) {
	raw := rawKernelEventV2{
		SchemaVersion:       SchemaVersion,
		EventType:           EventTypeExecAttempt,
		CapturedArgcPlusOne: 4,
	}
	copy(raw.Data[:execExecutableLength], "/usr/bin/tool")
	copy(raw.Data[execExecutableLength:], "tool")
	// The second argument is a legal empty string.
	copy(raw.Data[execExecutableLength+2*execArgumentLength:], "after-empty")

	event := decodeRawForTest(t, raw)
	wantArgv := []string{"tool", "", "after-empty"}
	if len(event.Argv) != len(wantArgv) {
		t.Fatalf("Argv = %#v, want %#v", event.Argv, wantArgv)
	}
	for i := range wantArgv {
		if event.Argv[i] != wantArgv[i] {
			t.Fatalf("Argv[%d] = %q, want %q", i, event.Argv[i], wantArgv[i])
		}
	}
	if event.CapturedArgc != 3 {
		t.Fatalf("CapturedArgc = %d, want 3", event.CapturedArgc)
	}
}

func TestDecodeKernelExecEventRejectsInvalidCapturedArgc(t *testing.T) {
	raw := rawKernelEventV2{
		SchemaVersion:       SchemaVersion,
		EventType:           EventTypeExecAttempt,
		CapturedArgcPlusOne: execArgumentCount + 2,
	}

	_, err := decodeRawBytesForTest(t, raw)
	if !errors.Is(err, ErrMalformedKernelEvent) {
		t.Fatalf("DecodeKernelEvent error = %v, want ErrMalformedKernelEvent", err)
	}
}

func TestDecodeKernelExecEventRejectsMissingCapturedArgc(t *testing.T) {
	raw := rawKernelEventV2{
		SchemaVersion: SchemaVersion,
		EventType:     EventTypeExecAttempt,
	}

	_, err := decodeRawBytesForTest(t, raw)
	if !errors.Is(err, ErrMalformedKernelEvent) {
		t.Fatalf("DecodeKernelEvent error = %v, want ErrMalformedKernelEvent", err)
	}
}

func TestDecodeKernelExecEventRejectsMaxUint32CapturedArgc(t *testing.T) {
	raw := rawKernelEventV2{
		SchemaVersion:       SchemaVersion,
		EventType:           EventTypeExecAttempt,
		CapturedArgcPlusOne: ^uint32(0),
	}

	_, err := decodeRawBytesForTest(t, raw)
	if !errors.Is(err, ErrMalformedKernelEvent) {
		t.Fatalf("DecodeKernelEvent error = %v, want ErrMalformedKernelEvent", err)
	}
}

func TestDecodeKernelEventRejectsWrongSize(t *testing.T) {
	sample := make([]byte, 3)
	binary.LittleEndian.PutUint16(sample, SchemaVersion)

	_, err := DecodeKernelEvent(sample)
	if !errors.Is(err, ErrMalformedKernelEvent) {
		t.Fatalf("DecodeKernelEvent error = %v, want ErrMalformedKernelEvent", err)
	}
}

func TestDecodeKernelEventRejectsSampleWithoutSchema(t *testing.T) {
	_, err := DecodeKernelEvent([]byte{1})
	if !errors.Is(err, ErrMalformedKernelEvent) {
		t.Fatalf("DecodeKernelEvent error = %v, want ErrMalformedKernelEvent", err)
	}
}

func TestDecodeKernelEventRejectsUnsupportedSchema(t *testing.T) {
	raw := rawKernelEventV2{SchemaVersion: SchemaVersion + 1}
	var buf bytes.Buffer
	if err := binary.Write(&buf, binary.LittleEndian, raw); err != nil {
		t.Fatalf("binary.Write: %v", err)
	}

	_, err := DecodeKernelEvent(buf.Bytes())
	if !errors.Is(err, ErrUnsupportedSchema) {
		t.Fatalf("DecodeKernelEvent error = %v, want ErrUnsupportedSchema", err)
	}
}

func TestDecodeKernelEventRejectsLegacyWireSchema(t *testing.T) {
	raw := rawKernelEventV2{SchemaVersion: SchemaVersion - 1}

	_, err := decodeRawBytesForTest(t, raw)
	if !errors.Is(err, ErrUnsupportedSchema) {
		t.Fatalf("DecodeKernelEvent error = %v, want ErrUnsupportedSchema", err)
	}
}

func TestDecodeKernelEventRejectsLargerFutureSchema(t *testing.T) {
	sample := make([]byte, KernelEventV2Size()+16)
	binary.LittleEndian.PutUint16(sample, SchemaVersion+1)

	_, err := DecodeKernelEvent(sample)
	if !errors.Is(err, ErrUnsupportedSchema) {
		t.Fatalf("DecodeKernelEvent error = %v, want ErrUnsupportedSchema", err)
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

func TestDecodeKernelEventEncodesInvalidUTF8WithoutReplacement(t *testing.T) {
	raw := rawKernelEventV2{
		SchemaVersion: SchemaVersion,
		EventType:     EventTypeFileOpen,
	}
	raw.Data[0] = 0xff
	raw.Data[1] = 0xfe

	event := decodeRawForTest(t, raw)
	if event.Data != "//4=" {
		t.Fatalf("Data = %q, want base64-encoded invalid bytes", event.Data)
	}
	if got := event.RawEncoding["data"]; got != "base64" {
		t.Fatalf("RawEncoding[data] = %q, want base64", got)
	}

	payload, err := json.Marshal(event)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	if bytes.Contains(payload, []byte(`\ufffd`)) {
		t.Fatalf("JSON contains a Unicode replacement character: %s", payload)
	}
}

func TestNameFallbacks(t *testing.T) {
	if ActionName(ActionContain) != "contain" {
		t.Fatal("contain action did not map to contain")
	}
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

func decodeRawForTest(t *testing.T, raw rawKernelEventV2) KernelEvent {
	t.Helper()

	event, err := decodeRawBytesForTest(t, raw)
	if err != nil {
		t.Fatalf("DecodeKernelEvent returned error: %v", err)
	}
	return event
}

func decodeRawBytesForTest(t *testing.T, raw rawKernelEventV2) (KernelEvent, error) {
	t.Helper()

	var buf bytes.Buffer
	if err := binary.Write(&buf, binary.LittleEndian, raw); err != nil {
		t.Fatalf("binary.Write: %v", err)
	}
	return DecodeKernelEvent(buf.Bytes())
}
