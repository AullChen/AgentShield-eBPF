package bpfmgr

import (
	"errors"
	"io"

	"github.com/agentshield/agentshield-ebpf/internal/events"
)

var ErrUnsupported = errors.New("bpf audit is not supported on this platform")

type AuditOptions struct {
	ObjectPath string
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
