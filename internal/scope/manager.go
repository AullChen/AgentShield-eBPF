package scope

import (
	"context"
	"errors"
	"fmt"
	"io"
	"path"
	"sync"
)

var (
	ErrInvalidTarget    = errors.New("scope target must select exactly one trusted cgroup path or PID")
	ErrIdentityMismatch = errors.New("resolved cgroup ID does not match BPF observation")
	ErrAlreadyActive    = errors.New("cgroup scope is already active")
	ErrOverlap          = errors.New("cgroup scope overlaps an active binding")
	ErrNotActive        = errors.New("cgroup scope is not active")
)

type Value struct {
	InstanceID  uint64
	ScopeCookie uint64
	ProfileID   uint32
	Reserved    uint32
}

type Map interface {
	Put(cgroupID uint64, value Value) error
	Delete(cgroupID uint64) error
}

type Resolver interface {
	ResolvePath(path string) (*Handle, error)
	ResolvePID(pid int) (*Handle, error)
}

type Probe interface {
	CurrentCgroupID(context.Context, *Handle) (uint64, error)
}

type Handle struct {
	ID     uint64
	Path   string
	closer io.Closer
	fd     int
	hasFD  bool
}

func (handle *Handle) Close() error {
	if handle == nil || handle.closer == nil {
		return nil
	}
	return handle.closer.Close()
}

type Target struct {
	Path string
	PID  int
}

type Registration struct {
	CgroupID uint64
	Path     string
	RootPID  int
	Value    Value
}

type Manager struct {
	mu       sync.Mutex
	scopes   Map
	resolver Resolver
	probe    Probe
	active   map[uint64]activeScope
}

type activeScope struct {
	registration Registration
	handle       *Handle
}

func NewManager(scopes Map, resolver Resolver, probe Probe) (*Manager, error) {
	if scopes == nil || resolver == nil || probe == nil {
		return nil, errors.New("scope map, resolver, and BPF identity probe are required")
	}
	return &Manager{
		scopes:   scopes,
		resolver: resolver,
		probe:    probe,
		active:   make(map[uint64]activeScope),
	}, nil
}

func (manager *Manager) Register(ctx context.Context, target Target, value Value) (Registration, error) {
	if (target.Path == "") == (target.PID == 0) {
		return Registration{}, ErrInvalidTarget
	}
	if value.InstanceID == 0 || value.ScopeCookie == 0 {
		return Registration{}, errors.New("instance ID and scope cookie must be non-zero")
	}

	var (
		handle *Handle
		err    error
	)
	if target.Path != "" {
		handle, err = manager.resolver.ResolvePath(target.Path)
	} else {
		if target.PID < 1 {
			return Registration{}, ErrInvalidTarget
		}
		handle, err = manager.resolver.ResolvePID(target.PID)
	}
	if err != nil {
		return Registration{}, fmt.Errorf("resolve exact leaf cgroup: %w", err)
	}
	if handle == nil || handle.ID == 0 || handle.Path == "" {
		if handle != nil {
			_ = handle.Close()
		}
		return Registration{}, errors.New("resolver returned an incomplete cgroup handle")
	}

	observedID, err := manager.probe.CurrentCgroupID(ctx, handle)
	if err != nil {
		_ = handle.Close()
		return Registration{}, fmt.Errorf("observe cgroup ID with BPF probe: %w", err)
	}
	if observedID != handle.ID {
		_ = handle.Close()
		return Registration{}, fmt.Errorf("%w: resolved=%d observed=%d", ErrIdentityMismatch, handle.ID, observedID)
	}

	manager.mu.Lock()
	defer manager.mu.Unlock()
	if _, exists := manager.active[handle.ID]; exists {
		_ = handle.Close()
		return Registration{}, fmt.Errorf("%w: %d", ErrAlreadyActive, handle.ID)
	}
	for _, active := range manager.active {
		if pathsOverlap(active.registration.Path, handle.Path) {
			_ = handle.Close()
			return Registration{}, fmt.Errorf("%w: %q and %q", ErrOverlap, active.registration.Path, handle.Path)
		}
	}
	if err := manager.scopes.Put(handle.ID, value); err != nil {
		_ = handle.Close()
		return Registration{}, fmt.Errorf("write scope map: %w", err)
	}

	registration := Registration{CgroupID: handle.ID, Path: handle.Path, RootPID: target.PID, Value: value}
	manager.active[handle.ID] = activeScope{registration: registration, handle: handle}
	return registration, nil
}

func (manager *Manager) Unregister(cgroupID uint64) error {
	manager.mu.Lock()
	defer manager.mu.Unlock()

	active, exists := manager.active[cgroupID]
	if !exists {
		return fmt.Errorf("%w: %d", ErrNotActive, cgroupID)
	}
	if err := manager.scopes.Delete(cgroupID); err != nil {
		return fmt.Errorf("delete scope map entry: %w", err)
	}
	delete(manager.active, cgroupID)
	if err := active.handle.Close(); err != nil {
		return fmt.Errorf("close cgroup handle: %w", err)
	}
	return nil
}

func pathsOverlap(first, second string) bool {
	first = path.Clean(first)
	second = path.Clean(second)
	return first == second ||
		first == "/" ||
		second == "/" ||
		len(first) < len(second) && second[:len(first)] == first && second[len(first)] == '/' ||
		len(second) < len(first) && first[:len(second)] == second && first[len(second)] == '/'
}

func (manager *Manager) Lookup(cgroupID uint64) (Registration, bool) {
	manager.mu.Lock()
	defer manager.mu.Unlock()
	active, exists := manager.active[cgroupID]
	return active.registration, exists
}

func (manager *Manager) ActiveIDs() []uint64 {
	manager.mu.Lock()
	defer manager.mu.Unlock()
	ids := make([]uint64, 0, len(manager.active))
	for id := range manager.active {
		ids = append(ids, id)
	}
	return ids
}
