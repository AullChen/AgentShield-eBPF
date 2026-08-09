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
	ObjectPath         string
	CgroupPath         string
	OnMalformedEvent   func(error)
	OnReady            func()
	OnScopeMapReady    func(ScopeMap) error
	DeriveRecords      func(AuditEvent) ([]any, error)
	NetworkEnforcement *NetworkEnforcementConfig
	ReceiptClock       ReceiptClock
	StatsInterval      time.Duration
}

type NetworkAllowTuple struct {
	AddressFamily uint16
	Port          uint16
	Address       [16]byte
	MatchFlags    uint32
}

const (
	NetworkAllowAnyAddress uint32 = 1 << iota
	NetworkAllowAnyPort
)

type NetworkEnforcementConfig struct {
	ProfileID  uint32
	Generation uint32
	PolicyID   uint32
	RuleID     uint32
	Allows     []NetworkAllowTuple
}

func (config NetworkEnforcementConfig) Validate() error {
	if config.ProfileID == 0 || config.Generation == 0 || config.PolicyID == 0 || config.RuleID == 0 {
		return errors.New("network enforcement profile, generation, policy, and rule IDs must be non-zero")
	}
	if len(config.Allows) > 1024 {
		return fmt.Errorf("network enforcement has %d allow tuples; capacity is 1024", len(config.Allows))
	}
	seen := make(map[NetworkAllowTuple]struct{}, len(config.Allows))
	for _, tuple := range config.Allows {
		if tuple.AddressFamily != events.AddressFamilyIPv4 && tuple.AddressFamily != events.AddressFamilyIPv6 {
			return fmt.Errorf("network enforcement address family %d is unsupported", tuple.AddressFamily)
		}
		if tuple.MatchFlags & ^(NetworkAllowAnyAddress|NetworkAllowAnyPort) != 0 {
			return fmt.Errorf("network enforcement match flags %#x are unsupported", tuple.MatchFlags)
		}
		if tuple.MatchFlags&(NetworkAllowAnyAddress|NetworkAllowAnyPort) ==
			NetworkAllowAnyAddress|NetworkAllowAnyPort {
			return errors.New("network enforcement tuple cannot wildcard both address and port")
		}
		if tuple.MatchFlags&NetworkAllowAnyPort != 0 && tuple.Port != 0 {
			return errors.New("network enforcement any-port tuple must use port zero")
		}
		if tuple.MatchFlags&NetworkAllowAnyPort == 0 && tuple.Port == 0 {
			return errors.New("network enforcement port zero requires the any-port flag")
		}
		if tuple.MatchFlags&NetworkAllowAnyAddress != 0 && tuple.Address != ([16]byte{}) {
			return errors.New("network enforcement any-address tuple must use an all-zero address")
		}
		if _, exists := seen[tuple]; exists {
			return fmt.Errorf("network enforcement allow tuple is duplicated: family=%d port=%d", tuple.AddressFamily, tuple.Port)
		}
		seen[tuple] = struct{}{}
	}
	return nil
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
	return emitter.EmitBatch(event)
}

func (emitter *auditEventEmitter) EmitBatch(records ...any) error {
	emitter.mu.Lock()
	defer emitter.mu.Unlock()
	for _, record := range records {
		if err := emitter.encoder.Encode(record); err != nil {
			return err
		}
	}
	return nil
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
		records := []any{event}
		if opts.DeriveRecords != nil {
			derived, err := opts.DeriveRecords(event)
			if err != nil {
				return fmt.Errorf("derive audit records: %w", err)
			}
			records = append(records, derived...)
		}
		if err := emitter.EmitBatch(records...); err != nil {
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
			current, err := reader.Snapshot()
			if err != nil {
				return fmt.Errorf("read final drop counters: %w", err)
			}
			return emitDeltas(current)
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
