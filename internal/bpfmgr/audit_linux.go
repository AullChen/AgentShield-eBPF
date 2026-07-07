//go:build linux

package bpfmgr

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

const (
	openATProgramName = "agentshield_trace_openat"
	eventsMapName     = "agentshield_events"
)

func RunOpenATAudit(ctx context.Context, opts OpenATAuditOptions, out io.Writer) error {
	if opts.ObjectPath == "" {
		return fmt.Errorf("bpf object path is required")
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		return fmt.Errorf("remove memlock limit: %w", err)
	}

	spec, err := ebpf.LoadCollectionSpec(opts.ObjectPath)
	if err != nil {
		return fmt.Errorf("load bpf collection spec %q: %w", opts.ObjectPath, err)
	}

	collection, err := ebpf.NewCollection(spec)
	if err != nil {
		return fmt.Errorf("load bpf collection: %w", err)
	}
	defer collection.Close()

	program := collection.Programs[openATProgramName]
	if program == nil {
		return fmt.Errorf("bpf program %q not found", openATProgramName)
	}
	events := collection.Maps[eventsMapName]
	if events == nil {
		return fmt.Errorf("bpf map %q not found", eventsMapName)
	}

	tracepoint, err := link.Tracepoint("syscalls", "sys_enter_openat", program, nil)
	if err != nil {
		return fmt.Errorf("attach openat tracepoint: %w", err)
	}
	defer tracepoint.Close()

	reader, err := ringbuf.NewReader(events)
	if err != nil {
		return fmt.Errorf("open ring buffer reader: %w", err)
	}
	defer reader.Close()

	go func() {
		<-ctx.Done()
		_ = reader.Close()
	}()

	encoder := json.NewEncoder(outputWriter(out))
	for {
		record, err := reader.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return nil
			}
			return fmt.Errorf("read ring buffer: %w", err)
		}

		event, err := DecodeAuditEvent(record.RawSample)
		if err != nil {
			return err
		}
		if err := encoder.Encode(event); err != nil {
			return fmt.Errorf("write audit event: %w", err)
		}
	}
}
