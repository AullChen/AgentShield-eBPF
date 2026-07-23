package bpfmgr

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"sync"
	"time"

	"github.com/agentshield/agentshield-ebpf/internal/events"
	"github.com/agentshield/agentshield-ebpf/internal/scope"
)

var ErrUnsupported = errors.New("bpf audit is not supported on this platform")

const maxConsecutiveMalformedEvents = 3
const maxMalformedEventNotifications = 3
const defaultStatsInterval = 5 * time.Second

type ReceiptTime struct {
	MonotonicNS        uint64
	UnixNS             uint64
	CalibrationErrorNS uint64
}

type ReceiptClock func() (ReceiptTime, error)

type AuditOptions struct {
	ObjectPath       string
	CgroupPath       string
	OnMalformedEvent func(error)
	OnReady          func()
	OnScopeMapReady  func(ScopeMap) error
	ReceiptClock     ReceiptClock
	StatsInterval    time.Duration
}

type ScopeMap interface {
	Put(cgroupID uint64, value scope.Value) error
	Delete(cgroupID uint64) error
}

type AuditEvent = events.KernelEvent

func DecodeAuditEvent(sample []byte) (AuditEvent, error) {
	return events.DecodeKernelEvent(sample)
}

func outputWriter(out io.Writer) io.Writer {
	if out == nil {
		return io.Discard
	}
	return out
}

type auditSampleReader interface {
	Next() ([]byte, error)
}

type auditSampleReaderFunc func() ([]byte, error)

func (read auditSampleReaderFunc) Next() ([]byte, error) {
	return read()
}

type auditEventEmitter struct {
	mu      sync.Mutex
	encoder *json.Encoder
}

func newAuditEventEmitter(out io.Writer) *auditEventEmitter {
	return &auditEventEmitter{encoder: json.NewEncoder(outputWriter(out))}
}

func (emitter *auditEventEmitter) Emit(event AuditEvent) error {
	emitter.mu.Lock()
	defer emitter.mu.Unlock()
	return emitter.encoder.Encode(event)
}

func streamAuditEvents(reader auditSampleReader, opts AuditOptions, out io.Writer) error {
	return streamAuditEventsTo(reader, opts, newAuditEventEmitter(out))
}

func streamAuditEventsTo(reader auditSampleReader, opts AuditOptions, emitter *auditEventEmitter) error {
	consecutiveMalformed := 0
	malformedNotifications := 0
	for {
		sample, err := reader.Next()
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return fmt.Errorf("read ring buffer: %w", err)
		}

		event, err := DecodeAuditEvent(sample)
		if err != nil {
			if errors.Is(err, events.ErrMalformedKernelEvent) {
				consecutiveMalformed++
				if opts.OnMalformedEvent != nil && malformedNotifications < maxMalformedEventNotifications {
					opts.OnMalformedEvent(err)
					malformedNotifications++
				}
				if consecutiveMalformed >= maxConsecutiveMalformedEvents {
					return fmt.Errorf("decode audit event: %d consecutive malformed records; BPF object and decoder ABI may not match: %w", consecutiveMalformed, err)
				}
				continue
			}
			return fmt.Errorf("decode audit event: %w", err)
		}
		consecutiveMalformed = 0
		if err := stampReceiptTime(&event, opts.ReceiptClock); err != nil {
			return fmt.Errorf("sample receipt clocks: %w", err)
		}
		if err := emitter.Emit(event); err != nil {
			return fmt.Errorf("write audit event: %w", err)
		}
	}
}

type dropCounterReader interface {
	Snapshot() (map[uint16]uint64, error)
}

func monitorDropCounters(ctx context.Context, interval time.Duration, reader dropCounterReader, clock ReceiptClock, emitter *auditEventEmitter) error {
	if interval <= 0 {
		interval = defaultStatsInterval
	}
	previous := make(map[uint16]uint64)
	emitDeltas := func(current map[uint16]uint64) error {
		keys := make([]int, 0, len(current))
		for eventType := range current {
			keys = append(keys, int(eventType))
		}
		sort.Ints(keys)
		for _, key := range keys {
			eventType := uint16(key)
			value := current[eventType]
			prior := previous[eventType]
			delta := value
			if value >= prior {
				delta = value - prior
			}
			if delta == 0 {
				continue
			}
			event := AuditEvent{
				JSONSchemaVersion:    events.JSONSchemaVersion,
				SchemaVersion:        events.WireSchemaVersion,
				EventType:            events.EventTypeDropNotice,
				EventTypeName:        events.EventTypeName(events.EventTypeDropNotice),
				Action:               events.ActionAudit,
				ActionName:           events.ActionName(events.ActionAudit),
				ActionResult:         events.ActionResultNone,
				ActionResultName:     events.ActionResultName(events.ActionResultNone),
				DroppedEventType:     eventType,
				DroppedEventTypeName: events.EventTypeName(eventType),
				DroppedCount:         delta,
			}
			if err := stampReceiptTime(&event, clock); err != nil {
				return fmt.Errorf("drop notice receipt clocks: %w", err)
			}
			if err := emitter.Emit(event); err != nil {
				return fmt.Errorf("write drop notice: %w", err)
			}
		}
		previous = current
		return nil
	}

	current, err := reader.Snapshot()
	if err != nil {
		return fmt.Errorf("read initial drop counters: %w", err)
	}
	if err := emitDeltas(current); err != nil {
		return err
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			current, err := reader.Snapshot()
			if err != nil {
				return fmt.Errorf("read drop counters: %w", err)
			}
			if err := emitDeltas(current); err != nil {
				return err
			}
		}
	}
}

func stampReceiptTime(event *AuditEvent, clock ReceiptClock) error {
	if clock == nil {
		return nil
	}
	receipt, err := clock()
	if err != nil {
		return err
	}
	event.ServerReceivedMonotonicNS = receipt.MonotonicNS
	event.ServerReceivedUnixNS = receipt.UnixNS
	event.ClockCalibrationErrorNS = receipt.CalibrationErrorNS
	return nil
}

func interruptOnContextDone(ctx context.Context, interrupt func()) func() {
	finished := make(chan struct{})
	stop := context.AfterFunc(ctx, func() {
		defer close(finished)
		interrupt()
	})

	return func() {
		if !stop() {
			<-finished
		}
	}
}
