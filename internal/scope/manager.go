package scope

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"sync"
)

var (
	ErrInvalidTarget    = errors.New("scope target requires one trusted exact cgroup path")
	ErrIdentityMismatch = errors.New("resolved cgroup ID does not match BPF observation")
	ErrAlreadyActive    = errors.New("cgroup scope is already active")
	ErrOverlap          = errors.New("cgroup scope overlaps an active binding")
	ErrNotActive        = errors.New("cgroup scope is not active")
	ErrProtectedScope   = errors.New("cgroup scope contains AgentShield-Core")
	ErrNotLeaf          = errors.New("cgroup scope is not an exact leaf")
)

type Value struct {
	InstanceID  uint64
	ScopeCookie uint64
	ProfileID   uint32
	Reserved    uint32
}

func (value Value) Validate() error {
	if value.InstanceID == 0 || value.ScopeCookie == 0 {
		return errors.New("instance ID and scope cookie must be non-zero")
	}
	if value.Reserved != 0 {
		return errors.New("reserved scope value field must be zero")
	}
	return nil
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
	root   string
}

func (handle *Handle) Close() error {
	if handle == nil || handle.closer == nil {
		return nil
	}
	return handle.closer.Close()
}

type Target struct {
	Path    string
	RootPID int
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
	corePath string
}

type activeScope struct {
	registration Registration
	handle       *Handle
}

func NewManager(scopes Map, resolver Resolver, probe Probe) (*Manager, error) {
	if scopes == nil || resolver == nil || probe == nil {
		return nil, errors.New("scope map, resolver, and BPF identity probe are required")
	}
	core, err := resolver.ResolvePID(os.Getpid())
	if err != nil {
		return nil, fmt.Errorf("resolve AgentShield-Core cgroup: %w", err)
	}
	if core == nil || core.ID == 0 || core.Path == "" {
		if core != nil {
			_ = core.Close()
		}
		return nil, errors.New("resolver returned an incomplete AgentShield-Core cgroup handle")
	}
	corePath := path.Clean(core.Path)
	if err := core.Close(); err != nil {
		return nil, fmt.Errorf("close AgentShield-Core cgroup handle: %w", err)
	}
	return &Manager{
		scopes:   scopes,
		resolver: resolver,
		probe:    probe,
		active:   make(map[uint64]activeScope),
		corePath: corePath,
	}, nil
}

func (manager *Manager) Register(ctx context.Context, target Target, value Value) (Registration, error) {
	if target.Path == "" {
		return Registration{}, ErrInvalidTarget
	}
	if target.RootPID < 0 {
		return Registration{}, ErrInvalidTarget
	}
	if err := value.Validate(); err != nil {
		return Registration{}, err
	}

	handle, err := manager.resolver.ResolvePath(target.Path)
	if err != nil {
		return Registration{}, fmt.Errorf("resolve exact leaf cgroup: %w", err)
	}
	if handle == nil || handle.ID == 0 || handle.Path == "" {
		if handle != nil {
			_ = handle.Close()
		}
		return Registration{}, errors.New("resolver returned an incomplete cgroup handle")
	}
	if pathIsEqualOrAncestor(handle.Path, manager.corePath) {
		_ = handle.Close()
		return Registration{}, fmt.Errorf("%w: target=%q core=%q", ErrProtectedScope, handle.Path, manager.corePath)
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

	registration := Registration{CgroupID: handle.ID, Path: handle.Path, RootPID: target.RootPID, Value: value}
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
	// The scope is detached once the map entry is gone. On Linux, close errors
	// do not make the descriptor safe to retry and must not roll back the Run
	// while its kernel scope is already absent.
	_ = active.handle.Close()
	return nil
}

func pathsOverlap(first, second string) bool {
	return pathIsEqualOrAncestor(first, second) || pathIsEqualOrAncestor(second, first)
}

func pathIsEqualOrAncestor(candidate, descendant string) bool {
	candidate = path.Clean(candidate)
	descendant = path.Clean(descendant)
	return candidate == descendant ||
		candidate == "/" ||
		len(candidate) < len(descendant) &&
			descendant[:len(candidate)] == candidate &&
			descendant[len(candidate)] == '/'
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
