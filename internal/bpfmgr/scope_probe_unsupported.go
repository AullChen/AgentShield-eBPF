//go:build !linux

package bpfmgr

import (
	"context"

	"github.com/agentshield/agentshield-ebpf/internal/scope"
)

type LinuxScopeProbe struct{}

func (LinuxScopeProbe) CurrentCgroupID(context.Context, *scope.Handle) (uint64, error) {
	return 0, ErrUnsupported
}
func ProbeCurrentCgroup() (uint64, error) { return 0, ErrUnsupported }
