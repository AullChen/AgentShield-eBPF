package bpfmgr

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"sync"
	"testing"
	"time"

	"github.com/agentshield/agentshield-ebpf/internal/events"
)

type rawAuditEventV2 struct {
	SchemaVersion       uint16
	EventType           uint16
	Action              uint16
	ActionResult        uint16
	TimestampNS         uint64
	CgroupID            uint64
	InstanceID          uint64
	ScopeCookie         uint64
	PID                 uint32
	TGID                uint32
	PPID                uint32
	UID                 uint32
	ProfileID           uint32
	PolicyID            uint32
	RuleID              uint32
	Flags               uint32
	SyscallFlags        uint32
	CapturedArgcPlusOne uint32
	Comm                [16]byte
	Data                [256]byte
}

func TestDecodeAuditEvent(t *testing.T) {
	raw := rawAuditEventV2{
		SchemaVersion: events.SchemaVersion,
		EventType:     events.EventTypeFileOpen,
		Action:        events.ActionAudit,
		ActionResult:  events.ActionResultNone,
		TimestampNS:   42,
		CgroupID:      77,
		InstanceID:    88,
		ScopeCookie:   99,
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
	if event.ActionResultName != "none" {
		t.Fatalf("ActionResultName = %q, want none", event.ActionResultName)
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
	sample := make([]byte, 3)
	binary.LittleEndian.PutUint16(sample, events.SchemaVersion)
	if _, err := DecodeAuditEvent(sample); !errors.Is(err, events.ErrMalformedKernelEvent) {
		t.Fatalf("DecodeAuditEvent error = %v, want ErrMalformedKernelEvent", err)
	}
}

func TestStreamAuditEventsSkipsMalformedSample(t *testing.T) {
	valid := encodeAuditSample(t, rawAuditEventV2{
		SchemaVersion: events.SchemaVersion,
		EventType:     events.EventTypeFileOpen,
		Action:        events.ActionAudit,
		ActionResult:  events.ActionResultNone,
		PID:           42,
	})
	samples := [][]byte{{1}, valid}
	next := 0
	var malformed []error
	var out bytes.Buffer

	err := streamAuditEvents(auditSampleReaderFunc(func() ([]byte, error) {
		if next == len(samples) {
			return nil, io.EOF
		}
		sample := samples[next]
		next++
		return sample, nil
	}), AuditOptions{OnMalformedEvent: func(err error) {
		malformed = append(malformed, err)
	}}, &out)
	if err != nil {
		t.Fatalf("streamAuditEvents returned error: %v", err)
	}
	if len(malformed) != 1 || !errors.Is(malformed[0], events.ErrMalformedKernelEvent) {
		t.Fatalf("malformed callbacks = %v, want one ErrMalformedKernelEvent", malformed)
	}

	var event AuditEvent
	if err := json.Unmarshal(out.Bytes(), &event); err != nil {
		t.Fatalf("decode output: %v", err)
	}
	if event.PID != 42 {
		t.Fatalf("output PID = %d, want 42", event.PID)
	}
}

func TestStreamAuditEventsStopsAfterConsecutiveMalformedSamples(t *testing.T) {
	reads := 0
	callbacks := 0
	reader := auditSampleReaderFunc(func() ([]byte, error) {
		reads++
		return []byte{1}, nil
	})

	err := streamAuditEvents(reader, AuditOptions{OnMalformedEvent: func(error) {
		callbacks++
	}}, io.Discard)
	if !errors.Is(err, events.ErrMalformedKernelEvent) {
		t.Fatalf("streamAuditEvents error = %v, want ErrMalformedKernelEvent", err)
	}
	if reads != maxConsecutiveMalformedEvents {
		t.Fatalf("reads = %d, want %d", reads, maxConsecutiveMalformedEvents)
	}
	if callbacks != maxConsecutiveMalformedEvents {
		t.Fatalf("callbacks = %d, want %d", callbacks, maxConsecutiveMalformedEvents)
	}
}

func TestStreamAuditEventsValidSampleResetsMalformedThreshold(t *testing.T) {
	valid := encodeAuditSample(t, rawAuditEventV2{
		SchemaVersion: events.SchemaVersion,
		EventType:     events.EventTypeFileOpen,
	})
	samples := [][]byte{{1}, {1}, valid, {1}, {1}, valid}
	next := 0

	err := streamAuditEvents(auditSampleReaderFunc(func() ([]byte, error) {
		if next == len(samples) {
			return nil, io.EOF
		}
		sample := samples[next]
		next++
		return sample, nil
	}), AuditOptions{}, io.Discard)
	if err != nil {
		t.Fatalf("streamAuditEvents returned error: %v", err)
	}
}

func TestStreamAuditEventsCapsMalformedNotifications(t *testing.T) {
	valid := encodeAuditSample(t, rawAuditEventV2{
		SchemaVersion: events.SchemaVersion,
		EventType:     events.EventTypeFileOpen,
	})
	samples := make([][]byte, 0, 2*(maxMalformedEventNotifications+2))
	for range maxMalformedEventNotifications + 2 {
		samples = append(samples, []byte{1}, valid)
	}
	next := 0
	notifications := 0

	err := streamAuditEvents(auditSampleReaderFunc(func() ([]byte, error) {
		if next == len(samples) {
			return nil, io.EOF
		}
		sample := samples[next]
		next++
		return sample, nil
	}), AuditOptions{OnMalformedEvent: func(error) {
		notifications++
	}}, io.Discard)
	if err != nil {
		t.Fatalf("streamAuditEvents returned error: %v", err)
	}
	if notifications != maxMalformedEventNotifications {
		t.Fatalf("malformed notifications = %d, want %d", notifications, maxMalformedEventNotifications)
	}
}

func TestStreamAuditEventsRejectsFutureSchema(t *testing.T) {
	future := encodeAuditSample(t, rawAuditEventV2{SchemaVersion: events.SchemaVersion + 1})
	reader := auditSampleReaderFunc(func() ([]byte, error) {
		return future, nil
	})

	err := streamAuditEvents(reader, AuditOptions{}, io.Discard)
	if !errors.Is(err, events.ErrUnsupportedSchema) {
		t.Fatalf("streamAuditEvents error = %v, want ErrUnsupportedSchema", err)
	}
}

func TestStreamAuditEventsReturnsReadError(t *testing.T) {
	wantErr := errors.New("read failed")
	reader := auditSampleReaderFunc(func() ([]byte, error) {
		return nil, wantErr
	})

	err := streamAuditEvents(reader, AuditOptions{}, io.Discard)
	if !errors.Is(err, wantErr) {
		t.Fatalf("streamAuditEvents error = %v, want wrapped read error", err)
	}
}

func TestStreamAuditEventsReturnsWriteError(t *testing.T) {
	wantErr := errors.New("write failed")
	valid := encodeAuditSample(t, rawAuditEventV2{
		SchemaVersion: events.SchemaVersion,
		EventType:     events.EventTypeFileOpen,
	})
	reader := auditSampleReaderFunc(func() ([]byte, error) {
		return valid, nil
	})

	err := streamAuditEvents(reader, AuditOptions{}, errorWriter{err: wantErr})
	if !errors.Is(err, wantErr) {
		t.Fatalf("streamAuditEvents error = %v, want wrapped write error", err)
	}
}

func TestStreamAuditEventsStampsReceiptClocks(t *testing.T) {
	valid := encodeAuditSample(t, rawAuditEventV2{
		SchemaVersion: events.SchemaVersion,
		EventType:     events.EventTypeFileOpen,
		TimestampNS:   101,
	})
	read := false
	var out bytes.Buffer

	err := streamAuditEvents(auditSampleReaderFunc(func() ([]byte, error) {
		if read {
			return nil, io.EOF
		}
		read = true
		return valid, nil
	}), AuditOptions{ReceiptClock: func() (ReceiptTime, error) {
		return ReceiptTime{MonotonicNS: 202, UnixNS: 303, CalibrationErrorNS: 4}, nil
	}}, &out)
	if err != nil {
		t.Fatalf("streamAuditEvents returned error: %v", err)
	}

	var event AuditEvent
	if err := json.Unmarshal(out.Bytes(), &event); err != nil {
		t.Fatalf("decode output: %v", err)
	}
	if event.TimestampNS != 101 || event.KernelMonotonicNS != 101 {
		t.Fatalf("kernel clocks = %d/%d, want 101/101", event.TimestampNS, event.KernelMonotonicNS)
	}
	if event.ServerReceivedMonotonicNS != 202 || event.ServerReceivedUnixNS != 303 || event.ClockCalibrationErrorNS != 4 {
		t.Fatalf("receipt clocks = %d/%d +/- %d, want 202/303 +/- 4", event.ServerReceivedMonotonicNS, event.ServerReceivedUnixNS, event.ClockCalibrationErrorNS)
	}
}

func TestStreamAuditEventsReturnsReceiptClockError(t *testing.T) {
	wantErr := errors.New("clock failed")
	valid := encodeAuditSample(t, rawAuditEventV2{SchemaVersion: events.SchemaVersion})
	reader := auditSampleReaderFunc(func() ([]byte, error) { return valid, nil })

	err := streamAuditEvents(reader, AuditOptions{ReceiptClock: func() (ReceiptTime, error) {
		return ReceiptTime{}, wantErr
	}}, io.Discard)
	if !errors.Is(err, wantErr) {
		t.Fatalf("streamAuditEvents error = %v, want clock error", err)
	}
}

func TestMonitorDropCountersEmitsDeltaAndStops(t *testing.T) {
	reader := &sequenceDropReader{snapshots: []map[uint16]uint64{
		{events.EventTypeFileOpen: 0},
		{events.EventTypeFileOpen: 3},
	}}
	writes := make(chan []byte, 1)
	emitter := newAuditEventEmitter(channelWriter{writes: writes})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- monitorDropCounters(ctx, time.Millisecond, reader, func() (ReceiptTime, error) {
			return ReceiptTime{MonotonicNS: 10, UnixNS: 20, CalibrationErrorNS: 1}, nil
		}, emitter)
	}()

	var payload []byte
	select {
	case payload = <-writes:
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for drop notice")
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("monitorDropCounters returned error: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("monitorDropCounters did not stop after cancellation")
	}

	var event AuditEvent
	if err := json.Unmarshal(payload, &event); err != nil {
		t.Fatalf("decode drop notice: %v", err)
	}
	if event.EventType != events.EventTypeDropNotice || event.DroppedEventType != events.EventTypeFileOpen || event.DroppedCount != 3 {
		t.Fatalf("drop notice = %+v, want file_open delta 3", event)
	}
	if event.ServerReceivedMonotonicNS != 10 || event.ServerReceivedUnixNS != 20 {
		t.Fatalf("drop notice receipt clocks = %d/%d", event.ServerReceivedMonotonicNS, event.ServerReceivedUnixNS)
	}
}

func TestMonitorDropCountersEmitsInitialNonzeroCounts(t *testing.T) {
	reader := &sequenceDropReader{snapshots: []map[uint16]uint64{
		{events.EventTypeExecAttempt: 2},
	}}
	writes := make(chan []byte, 1)
	emitter := newAuditEventEmitter(channelWriter{writes: writes})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		done <- monitorDropCounters(ctx, time.Hour, reader, nil, emitter)
	}()

	select {
	case payload := <-writes:
		var event AuditEvent
		if err := json.Unmarshal(payload, &event); err != nil {
			t.Fatalf("decode initial drop notice: %v", err)
		}
		if event.DroppedEventType != events.EventTypeExecAttempt || event.DroppedCount != 2 {
			t.Fatalf("initial drop notice = %+v, want exec_attempt count 2", event)
		}
	case <-time.After(time.Second):
		t.Fatal("initial nonzero drop counters were not emitted")
	}

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("monitorDropCounters returned error: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("monitorDropCounters did not stop after cancellation")
	}
}

func TestMonitorDropCountersEmitsFinalDeltaOnCancellation(t *testing.T) {
	reader := &shutdownDropReader{initialized: make(chan struct{})}
	writes := make(chan []byte, 1)
	emitter := newAuditEventEmitter(channelWriter{writes: writes})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- monitorDropCounters(ctx, time.Hour, reader, nil, emitter)
	}()

	select {
	case <-reader.initialized:
	case <-time.After(time.Second):
		t.Fatal("initial drop-counter snapshot did not complete")
	}
	cancel()

	select {
	case payload := <-writes:
		var event AuditEvent
		if err := json.Unmarshal(payload, &event); err != nil {
			t.Fatalf("decode final drop notice: %v", err)
		}
		if event.DroppedEventType != events.EventTypeFileOpen || event.DroppedCount != 4 {
			t.Fatalf("final drop notice = %+v, want file_open delta 4", event)
		}
	case <-time.After(time.Second):
		t.Fatal("final drop-counter delta was not emitted on cancellation")
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("monitorDropCounters returned error: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("monitorDropCounters did not stop after final snapshot")
	}
}

func TestInterruptOnContextDoneStopsWithoutInterrupting(t *testing.T) {
	interrupted := false
	stop := interruptOnContextDone(context.Background(), func() {
		interrupted = true
	})

	stop()
	if interrupted {
		t.Fatal("interrupt called before context cancellation")
	}
}

func TestInterruptOnContextDoneInterruptsAfterCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	interrupted := make(chan struct{})
	stop := interruptOnContextDone(ctx, func() {
		close(interrupted)
	})

	cancel()
	stop()
	select {
	case <-interrupted:
	default:
		t.Fatal("interrupt was not called after context cancellation")
	}
}

type errorWriter struct {
	err error
}

type channelWriter struct {
	writes chan<- []byte
}

func (writer channelWriter) Write(payload []byte) (int, error) {
	copyOfPayload := append([]byte(nil), payload...)
	writer.writes <- copyOfPayload
	return len(payload), nil
}

type sequenceDropReader struct {
	mu        sync.Mutex
	snapshots []map[uint16]uint64
	next      int
}

type shutdownDropReader struct {
	mu          sync.Mutex
	initialized chan struct{}
	calls       int
}

func (reader *shutdownDropReader) Snapshot() (map[uint16]uint64, error) {
	reader.mu.Lock()
	defer reader.mu.Unlock()
	reader.calls++
	if reader.calls == 1 {
		close(reader.initialized)
		return map[uint16]uint64{events.EventTypeFileOpen: 0}, nil
	}
	return map[uint16]uint64{events.EventTypeFileOpen: 4}, nil
}

func (reader *sequenceDropReader) Snapshot() (map[uint16]uint64, error) {
	reader.mu.Lock()
	defer reader.mu.Unlock()
	if len(reader.snapshots) == 0 {
		return map[uint16]uint64{}, nil
	}
	index := reader.next
	if index >= len(reader.snapshots) {
		index = len(reader.snapshots) - 1
	} else {
		reader.next++
	}
	result := make(map[uint16]uint64, len(reader.snapshots[index]))
	for key, value := range reader.snapshots[index] {
		result[key] = value
	}
	return result, nil
}

func (w errorWriter) Write([]byte) (int, error) {
	return 0, w.err
}

func encodeAuditSample(t *testing.T, raw rawAuditEventV2) []byte {
	t.Helper()

	if raw.CgroupID == 0 {
		raw.CgroupID = 1
	}
	if raw.InstanceID == 0 {
		raw.InstanceID = 2
	}
	if raw.ScopeCookie == 0 {
		raw.ScopeCookie = 3
	}
	var buf bytes.Buffer
	if err := binary.Write(&buf, binary.LittleEndian, raw); err != nil {
		t.Fatalf("binary.Write: %v", err)
	}
	return buf.Bytes()
}
