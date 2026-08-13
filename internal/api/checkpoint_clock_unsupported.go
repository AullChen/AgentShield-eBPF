//go:build !linux

package api

import (
	"errors"
	"time"
)

func captureCheckpointReceiptTime() (CheckpointReceiptTime, error) {
	now := time.Now().UTC()
	if now.UnixNano() < 0 {
		return CheckpointReceiptTime{}, errors.New("system clock returned a pre-epoch time")
	}
	elapsed := time.Since(processMonotonicOrigin).Nanoseconds()
	if elapsed < 0 {
		return CheckpointReceiptTime{}, errors.New("monotonic clock moved backwards")
	}
	return CheckpointReceiptTime{
		MonotonicNS: uint64(elapsed) + 1,
		UnixNS:      uint64(now.UnixNano()),
		ErrorNS:     0,
	}, nil
}

var processMonotonicOrigin = time.Now()
