package killer

import (
	"context"
	"errors"
	"fmt"
	"path"

	"github.com/agentshield/agentshield-ebpf/internal/scope"
)

var (
	ErrUnsupported            = errors.New("containment is unsupported")
	ErrInvalidRequest         = errors.New("invalid containment request")
	ErrProtectedTarget        = errors.New("containment target includes AgentShield-Core")
	ErrCgroupIdentityMismatch = errors.New("opened cgroup does not match the active scope")
	ErrCgroupNotLeaf          = errors.New("containment target is not an exact leaf cgroup")
)

type EnforcementMethod string

const MethodCgroupKill EnforcementMethod = "cgroup_kill"

type EnforcementResult string

const (
	ResultNotAttempted EnforcementResult = "not_attempted"
	ResultKilled       EnforcementResult = "killed"
	ResultFailed       EnforcementResult = "failed"
)

type SyscallResult string

const (
	SyscallNotObserved SyscallResult = "not_observed"
	SyscallSucceeded   SyscallResult = "succeeded"
	SyscallFailed      SyscallResult = "failed"
)

// Request identifies one active Run scope. PID and TGID are correlation
// evidence only; cgroup containment never uses them to select the target.
type Request struct {
	KernelMonotonicNS uint64
	CgroupID          uint64
	InstanceID        uint64
	ScopeCookie       uint64
	PID               uint32
	TGID              uint32
	SyscallResult     SyscallResult
}

func (request Request) Validate() error {
	if request.CgroupID == 0 || request.InstanceID == 0 || request.ScopeCookie == 0 {
		return fmt.Errorf("%w: cgroup, instance, and scope cookie must be non-zero", ErrInvalidRequest)
	}
	switch request.SyscallResult {
	case SyscallNotObserved, SyscallSucceeded, SyscallFailed:
		return nil
	default:
		return fmt.Errorf("%w: syscall result %q is unsupported", ErrInvalidRequest, request.SyscallResult)
	}
}

// Outcome is emitted independently from the triggering kernel event. A
// successful post-event containment never changes SyscallResult to blocked.
type Outcome struct {
	RecordType        string            `json:"record_type"`
	KernelMonotonicNS uint64            `json:"kernel_monotonic_ns,string,omitempty"`
	CgroupID          uint64            `json:"cgroup_id,string"`
	InstanceID        uint64            `json:"instance_id,string"`
	ScopeCookie       uint64            `json:"scope_cookie,string"`
	PID               uint32            `json:"pid,omitempty"`
	TGID              uint32            `json:"tgid,omitempty"`
	SyscallResult     SyscallResult     `json:"syscall_result"`
	EnforcementMethod EnforcementMethod `json:"enforcement_method"`
	EnforcementResult EnforcementResult `json:"enforcement_result"`
	Reason            string            `json:"reason,omitempty"`
}

type ScopeAuthorizer interface {
	WithActiveIdentity(
		cgroupID, instanceID, scopeCookie uint64,
		action func(scope.Registration, *scope.Handle) error,
	) error
}

type CgroupIdentity struct {
	ID   uint64
	Path string
}

type CgroupHandle interface {
	Identity() CgroupIdentity
	Kill(context.Context) error
	Close() error
}

type CgroupBackend interface {
	CurrentCoreCgroup(context.Context) (CgroupIdentity, error)
	OpenCgroup(context.Context, *scope.Handle) (CgroupHandle, error)
}

type Executor struct {
	scopes  ScopeAuthorizer
	backend CgroupBackend
}

func NewExecutor(scopes ScopeAuthorizer, backend CgroupBackend) (*Executor, error) {
	if scopes == nil || backend == nil {
		return nil, errors.New("scope authorizer and cgroup backend are required")
	}
	return &Executor{scopes: scopes, backend: backend}, nil
}

func (executor *Executor) Contain(ctx context.Context, request Request) (Outcome, error) {
	outcome := newOutcome(request)
	if executor == nil {
		err := errors.New("containment executor is required")
		outcome.Reason = err.Error()
		return outcome, err
	}
	if ctx == nil {
		err := fmt.Errorf("%w: context is required", ErrInvalidRequest)
		outcome.Reason = err.Error()
		return outcome, err
	}
	if err := request.Validate(); err != nil {
		outcome.Reason = err.Error()
		return outcome, err
	}
	if err := ctx.Err(); err != nil {
		outcome.Reason = err.Error()
		return outcome, err
	}

	authorized := false
	safetyRejected := false
	err := executor.scopes.WithActiveIdentity(
		request.CgroupID,
		request.InstanceID,
		request.ScopeCookie,
		func(registration scope.Registration, trusted *scope.Handle) error {
			if registration.CgroupID != request.CgroupID {
				safetyRejected = true
				return fmt.Errorf("%w: registered=%d requested=%d",
					ErrCgroupIdentityMismatch, registration.CgroupID, request.CgroupID)
			}
			targetPath := path.Clean(registration.Path)
			if !path.IsAbs(targetPath) {
				safetyRejected = true
				return fmt.Errorf("%w: active scope path %q is not absolute", ErrCgroupIdentityMismatch, registration.Path)
			}
			if trusted == nil || trusted.ID != request.CgroupID || path.Clean(trusted.Path) != targetPath {
				safetyRejected = true
				return fmt.Errorf("%w: trusted handle does not match active registration", ErrCgroupIdentityMismatch)
			}
			authorized = true

			core, err := executor.backend.CurrentCoreCgroup(ctx)
			if err != nil {
				return fmt.Errorf("resolve current Core cgroup: %w", err)
			}
			if err := validateCgroupIdentity(core); err != nil {
				return fmt.Errorf("validate current Core cgroup: %w", err)
			}
			if cgroupContains(targetPath, request.CgroupID, core) {
				safetyRejected = true
				return fmt.Errorf("%w: target=%q core=%q", ErrProtectedTarget, targetPath, core.Path)
			}

			handle, err := executor.backend.OpenCgroup(ctx, trusted)
			if err != nil {
				if errors.Is(err, ErrCgroupIdentityMismatch) || errors.Is(err, ErrCgroupNotLeaf) {
					safetyRejected = true
				}
				return fmt.Errorf("open active cgroup: %w", err)
			}
			if handle == nil {
				return errors.New("cgroup backend returned a nil handle")
			}
			defer handle.Close()
			opened := handle.Identity()
			if err := validateCgroupIdentity(opened); err != nil {
				safetyRejected = true
				return fmt.Errorf("validate opened cgroup: %w", err)
			}
			if opened.ID != request.CgroupID || path.Clean(opened.Path) != targetPath {
				safetyRejected = true
				return fmt.Errorf("%w: opened=%d/%q active=%d/%q",
					ErrCgroupIdentityMismatch, opened.ID, opened.Path, request.CgroupID, targetPath)
			}
			if cgroupContains(opened.Path, opened.ID, core) {
				safetyRejected = true
				return fmt.Errorf("%w: target=%q core=%q", ErrProtectedTarget, opened.Path, core.Path)
			}
			latestCore, err := executor.backend.CurrentCoreCgroup(ctx)
			if err != nil {
				return fmt.Errorf("revalidate current Core cgroup: %w", err)
			}
			if err := validateCgroupIdentity(latestCore); err != nil {
				return fmt.Errorf("revalidate current Core cgroup: %w", err)
			}
			if cgroupContains(opened.Path, opened.ID, latestCore) {
				safetyRejected = true
				return fmt.Errorf("%w: target=%q core=%q", ErrProtectedTarget, opened.Path, latestCore.Path)
			}
			if err := ctx.Err(); err != nil {
				return err
			}
			if err := handle.Kill(ctx); err != nil {
				if errors.Is(err, ErrCgroupNotLeaf) {
					safetyRejected = true
				}
				return fmt.Errorf("write cgroup.kill: %w", err)
			}
			return nil
		},
	)
	if err != nil {
		if authorized && !safetyRejected {
			outcome.EnforcementResult = ResultFailed
		}
		outcome.Reason = err.Error()
		return outcome, err
	}
	outcome.EnforcementResult = ResultKilled
	return outcome, nil
}

func newOutcome(request Request) Outcome {
	return Outcome{
		RecordType:        "containment_result",
		KernelMonotonicNS: request.KernelMonotonicNS,
		CgroupID:          request.CgroupID,
		InstanceID:        request.InstanceID,
		ScopeCookie:       request.ScopeCookie,
		PID:               request.PID,
		TGID:              request.TGID,
		SyscallResult:     request.SyscallResult,
		EnforcementMethod: MethodCgroupKill,
		EnforcementResult: ResultNotAttempted,
	}
}

func validateCgroupIdentity(identity CgroupIdentity) error {
	if identity.ID == 0 || !path.IsAbs(identity.Path) {
		return fmt.Errorf("%w: incomplete cgroup identity %d/%q",
			ErrCgroupIdentityMismatch, identity.ID, identity.Path)
	}
	return nil
}

func cgroupContains(candidatePath string, candidateID uint64, member CgroupIdentity) bool {
	if candidateID == member.ID {
		return true
	}
	candidatePath = path.Clean(candidatePath)
	memberPath := path.Clean(member.Path)
	return candidatePath == memberPath || candidatePath == "/" ||
		len(candidatePath) < len(memberPath) &&
			memberPath[:len(candidatePath)] == candidatePath &&
			memberPath[len(candidatePath)] == '/'
}
