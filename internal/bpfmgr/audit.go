package bpfmgr

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"github.com/agentshield/agentshield-ebpf/internal/events"
)

var ErrUnsupported = errors.New("bpf audit is not supported on this platform")

const maxConsecutiveMalformedEvents = 3
const maxMalformedEventNotifications = 3

type AuditOptions struct {
	ObjectPath       string
	OnMalformedEvent func(error)
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

func streamAuditEvents(reader auditSampleReader, opts AuditOptions, out io.Writer) error {
	encoder := json.NewEncoder(outputWriter(out))
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
		if err := encoder.Encode(event); err != nil {
			return fmt.Errorf("write audit event: %w", err)
		}
	}
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
