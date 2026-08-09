//go:build linux

package bpfmgr

import (
	"context"
	"errors"
	"fmt"
	"io"

	"github.com/agentshield/agentshield-ebpf/internal/events"
	"github.com/agentshield/agentshield-ebpf/internal/scope"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/sys/unix"
)

const (
	openATProgramName     = "agentshield_trace_openat"
	execVEProgramName     = "agentshield_trace_execve"
	connect4ProgramName   = "agentshield_connect4"
	connect6ProgramName   = "agentshield_connect6"
	eventsMapName         = "agentshield_events"
	statsMapName          = "agentshield_stats_map"
	scopeMapName          = "agentshield_scope_map"
	networkProfileMapName = "agentshield_network_profile_map"
	networkAllowMapName   = "agentshield_network_allow_map"
	droppedStatsBase      = uint32(16)
)

const networkDefaultDeny = uint32(1)

type ebpfNetworkProfile struct {
	Generation uint32
	PolicyID   uint32
	RuleID     uint32
	Flags      uint32
}

type ebpfNetworkAllowKey struct {
	ProfileID          uint32
	Generation         uint32
	AddressFamily      uint16
	DestinationPort    uint16
	DestinationAddress [16]byte
	MatchFlags         uint32
}

type ebpfScopeMap struct {
	scopes *ebpf.Map
}

func (store ebpfScopeMap) Put(cgroupID uint64, value scope.Value) error {
	if cgroupID == 0 {
		return fmt.Errorf("cgroup ID must be non-zero")
	}
	if err := value.Validate(); err != nil {
		return fmt.Errorf("validate cgroup %d scope value: %w", cgroupID, err)
	}
	if err := store.scopes.Update(cgroupID, value, ebpf.UpdateNoExist); err != nil {
		return fmt.Errorf("update cgroup %d: %w", cgroupID, err)
	}
	return nil
}

func (store ebpfScopeMap) Delete(cgroupID uint64) error {
	if err := store.scopes.Delete(cgroupID); err != nil {
		return fmt.Errorf("delete cgroup %d: %w", cgroupID, err)
	}
	return nil
}

type ebpfDropCounterReader struct {
	stats        *ebpf.Map
	possibleCPUs int
}

func (reader ebpfDropCounterReader) Snapshot() (map[uint16]uint64, error) {
	snapshot := make(map[uint16]uint64)
	for eventType := uint16(events.EventTypeExecAttempt); eventType <= events.EventTypeSelfDiag; eventType++ {
		key := droppedStatsBase + uint32(eventType)
		values := make([]uint64, reader.possibleCPUs)
		if err := reader.stats.Lookup(key, &values); err != nil {
			return nil, fmt.Errorf("lookup event type %d: %w", eventType, err)
		}
		for _, value := range values {
			snapshot[eventType] += value
		}
	}
	return snapshot, nil
}

func RunAudit(ctx context.Context, opts AuditOptions, out io.Writer) error {
	if opts.ObjectPath == "" {
		return fmt.Errorf("bpf object path is required")
	}
	if opts.NetworkEnforcement != nil {
		if err := opts.NetworkEnforcement.Validate(); err != nil {
			return fmt.Errorf("validate network enforcement: %w", err)
		}
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		return fmt.Errorf("remove memlock limit: %w", err)
	}

	spec, err := ebpf.LoadCollectionSpec(opts.ObjectPath)
	if err != nil {
		return fmt.Errorf("load bpf collection spec %q: %w", opts.ObjectPath, err)
	}
	if opts.CgroupPath == "" {
		delete(spec.Programs, connect4ProgramName)
		delete(spec.Programs, connect6ProgramName)
	}

	collection, err := ebpf.NewCollection(spec)
	if err != nil {
		return fmt.Errorf("load bpf collection: %w", err)
	}
	defer collection.Close()

	openATProgram := collection.Programs[openATProgramName]
	if openATProgram == nil {
		return fmt.Errorf("bpf program %q not found", openATProgramName)
	}
	execVEProgram := collection.Programs[execVEProgramName]
	if execVEProgram == nil {
		return fmt.Errorf("bpf program %q not found", execVEProgramName)
	}
	events := collection.Maps[eventsMapName]
	if events == nil {
		return fmt.Errorf("bpf map %q not found", eventsMapName)
	}
	stats := collection.Maps[statsMapName]
	if stats == nil {
		return fmt.Errorf("bpf map %q not found", statsMapName)
	}
	scopes := collection.Maps[scopeMapName]
	if scopes == nil {
		return fmt.Errorf("bpf map %q not found", scopeMapName)
	}
	if opts.NetworkEnforcement != nil {
		profiles := collection.Maps[networkProfileMapName]
		if profiles == nil {
			return fmt.Errorf("bpf map %q not found", networkProfileMapName)
		}
		allows := collection.Maps[networkAllowMapName]
		if allows == nil {
			return fmt.Errorf("bpf map %q not found", networkAllowMapName)
		}
		if err := installNetworkEnforcement(profiles, allows, *opts.NetworkEnforcement); err != nil {
			return err
		}
	}
	if opts.OnScopeMapReady != nil {
		if err := opts.OnScopeMapReady(ebpfScopeMap{scopes: scopes}); err != nil {
			return fmt.Errorf("initialize scope manager: %w", err)
		}
	}
	possibleCPUs, err := ebpf.PossibleCPU()
	if err != nil {
		return fmt.Errorf("determine possible CPUs for per-CPU stats: %w", err)
	}
	dropReader := ebpfDropCounterReader{stats: stats, possibleCPUs: possibleCPUs}
	if opts.ReceiptClock == nil {
		opts.ReceiptClock = captureReceiptTime
	}

	openATTracepoint, err := link.Tracepoint("syscalls", "sys_enter_openat", openATProgram, nil)
	if err != nil {
		return fmt.Errorf("attach openat tracepoint: %w", err)
	}
	defer openATTracepoint.Close()

	execVETracepoint, err := link.Tracepoint("syscalls", "sys_enter_execve", execVEProgram, nil)
	if err != nil {
		return fmt.Errorf("attach execve tracepoint: %w", err)
	}
	defer execVETracepoint.Close()

	if opts.CgroupPath != "" {
		connect4Program := collection.Programs[connect4ProgramName]
		if connect4Program == nil {
			return fmt.Errorf("bpf program %q not found", connect4ProgramName)
		}
		connect6Program := collection.Programs[connect6ProgramName]
		if connect6Program == nil {
			return fmt.Errorf("bpf program %q not found", connect6ProgramName)
		}

		connect4Link, err := link.AttachCgroup(link.CgroupOptions{
			Path:    opts.CgroupPath,
			Attach:  ebpf.AttachCGroupInet4Connect,
			Program: connect4Program,
		})
		if err != nil {
			return fmt.Errorf("attach connect4 to cgroup %q: %w", opts.CgroupPath, err)
		}
		defer connect4Link.Close()

		connect6Link, err := link.AttachCgroup(link.CgroupOptions{
			Path:    opts.CgroupPath,
			Attach:  ebpf.AttachCGroupInet6Connect,
			Program: connect6Program,
		})
		if err != nil {
			return fmt.Errorf("attach connect6 to cgroup %q: %w", opts.CgroupPath, err)
		}
		defer connect6Link.Close()
	}

	reader, err := ringbuf.NewReader(events)
	if err != nil {
		return fmt.Errorf("open ring buffer reader: %w", err)
	}
	defer reader.Close()

	stopInterrupt := interruptOnContextDone(ctx, func() {
		_ = reader.Close()
	})
	defer stopInterrupt()

	emitter := newAuditEventEmitter(out)
	statsContext, cancelStats := context.WithCancel(ctx)
	statsDone := make(chan error, 1)
	go func() {
		err := monitorDropCounters(statsContext, opts.StatsInterval, dropReader, opts.ReceiptClock, emitter)
		if err != nil {
			_ = reader.Close()
		}
		statsDone <- err
	}()
	if opts.OnReady != nil {
		opts.OnReady()
	}

	streamErr := streamAuditEventsTo(auditSampleReaderFunc(func() ([]byte, error) {
		record, err := reader.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return nil, io.EOF
			}
			return nil, err
		}
		return record.RawSample, nil
	}), opts, emitter)
	cancelStats()
	statsErr := <-statsDone
	if streamErr != nil && statsErr != nil {
		return errors.Join(streamErr, statsErr)
	}
	if streamErr != nil {
		return streamErr
	}
	return statsErr
}

func installNetworkEnforcement(profiles, allows *ebpf.Map, config NetworkEnforcementConfig) error {
	for _, tuple := range config.Allows {
		key := ebpfNetworkAllowKey{
			ProfileID:          config.ProfileID,
			Generation:         config.Generation,
			AddressFamily:      tuple.AddressFamily,
			DestinationPort:    tuple.Port,
			DestinationAddress: tuple.Address,
			MatchFlags:         tuple.MatchFlags,
		}
		value := uint8(1)
		if err := allows.Update(key, value, ebpf.UpdateNoExist); err != nil {
			return fmt.Errorf("install network allow tuple family=%d port=%d: %w", tuple.AddressFamily, tuple.Port, err)
		}
	}
	profile := ebpfNetworkProfile{
		Generation: config.Generation,
		PolicyID:   config.PolicyID,
		RuleID:     config.RuleID,
		Flags:      networkDefaultDeny,
	}
	if err := profiles.Update(config.ProfileID, profile, ebpf.UpdateNoExist); err != nil {
		return fmt.Errorf("activate network enforcement profile %d: %w", config.ProfileID, err)
	}
	return nil
}

func captureReceiptTime() (ReceiptTime, error) {
	var before unix.Timespec
	var realtime unix.Timespec
	var after unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &before); err != nil {
		return ReceiptTime{}, fmt.Errorf("read monotonic clock before realtime: %w", err)
	}
	if err := unix.ClockGettime(unix.CLOCK_REALTIME, &realtime); err != nil {
		return ReceiptTime{}, fmt.Errorf("read realtime clock: %w", err)
	}
	if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &after); err != nil {
		return ReceiptTime{}, fmt.Errorf("read monotonic clock after realtime: %w", err)
	}

	beforeNS := before.Nano()
	afterNS := after.Nano()
	realtimeNS := realtime.Nano()
	if beforeNS < 0 || afterNS < beforeNS || realtimeNS < 0 {
		return ReceiptTime{}, errors.New("clock_gettime returned an invalid sample")
	}
	interval := uint64(afterNS - beforeNS)
	return ReceiptTime{
		MonotonicNS:        uint64(beforeNS) + interval/2,
		UnixNS:             uint64(realtimeNS),
		CalibrationErrorNS: (interval + 1) / 2,
	}, nil
}
