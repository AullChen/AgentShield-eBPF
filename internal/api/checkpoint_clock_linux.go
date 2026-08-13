//go:build linux

package api

import (
	"fmt"

	"github.com/agentshield/agentshield-ebpf/internal/timebase"
	"golang.org/x/sys/unix"
)

func captureCheckpointReceiptTime() (CheckpointReceiptTime, error) {
	var before, realtime, after unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &before); err != nil {
		return CheckpointReceiptTime{}, fmt.Errorf("read monotonic clock before realtime: %w", err)
	}
	if err := unix.ClockGettime(unix.CLOCK_REALTIME, &realtime); err != nil {
		return CheckpointReceiptTime{}, fmt.Errorf("read realtime clock: %w", err)
	}
	if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &after); err != nil {
		return CheckpointReceiptTime{}, fmt.Errorf("read monotonic clock after realtime: %w", err)
	}
	sample, err := timebase.Calibrate(before.Nano(), realtime.Nano(), after.Nano())
	if err != nil {
		return CheckpointReceiptTime{}, err
	}
	return CheckpointReceiptTime{
		MonotonicNS: sample.MonotonicNS,
		UnixNS:      sample.UnixNS,
		ErrorNS:     sample.ErrorNS,
	}, nil
}
