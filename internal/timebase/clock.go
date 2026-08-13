package timebase

import "errors"

// Sample contains one calibrated same-host receipt time. MonotonicNS is the
// midpoint of the samples surrounding UnixNS; ErrorNS is half that interval.
type Sample struct {
	MonotonicNS uint64
	UnixNS      uint64
	ErrorNS     uint64
}

// Calibrate validates and combines monotonic-before, realtime, and
// monotonic-after nanosecond readings.
func Calibrate(monotonicBeforeNS, unixNS, monotonicAfterNS int64) (Sample, error) {
	if monotonicBeforeNS < 0 || unixNS < 0 || monotonicAfterNS < monotonicBeforeNS {
		return Sample{}, errors.New("clock returned an invalid sample")
	}
	interval := uint64(monotonicAfterNS - monotonicBeforeNS)
	return Sample{
		MonotonicNS: uint64(monotonicBeforeNS) + interval/2,
		UnixNS:      uint64(unixNS),
		ErrorNS:     (interval + 1) / 2,
	}, nil
}
