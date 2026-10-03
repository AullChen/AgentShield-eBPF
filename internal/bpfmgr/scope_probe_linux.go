//go:build linux

package bpfmgr

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/agentshield/agentshield-ebpf/internal/scope"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/link"
	"golang.org/x/sys/unix"
)

// LinuxScopeProbe starts a short-lived copy of Core directly in the held
// cgroup using clone3. Core's own process/thread never changes cgroup.
type LinuxScopeProbe struct{}

func (LinuxScopeProbe) CurrentCgroupID(ctx context.Context, handle *scope.Handle) (uint64, error) {
	fd, err := handle.DuplicateFD()
	if err != nil {
		return 0, err
	}
	file := os.NewFile(uintptr(fd), "scope-probe-cgroup")
	defer file.Close()
	executable, err := os.Executable()
	if err != nil {
		return 0, err
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, executable, "internal-scope-probe")
	command.SysProcAttr = &syscall.SysProcAttr{UseCgroupFD: true, CgroupFD: fd}
	// Preserve actual helper/verifier diagnostics in Core's operator log;
	// the child handles only this fixed probe, not Agent data or credentials.
	command.Stderr = os.Stderr
	output, err := command.Output()
	if err != nil {
		return 0, fmt.Errorf("BPF scope probe child failed: %w", err)
	}
	id, err := strconv.ParseUint(strings.TrimSpace(string(output)), 10, 64)
	if err != nil || id == 0 {
		return 0, errors.New("BPF scope probe returned an invalid identity")
	}
	return id, nil
}

// ProbeCurrentCgroup uses the kernel helper in the child to independently
// cross-check the resolver's inode-derived identity.
func ProbeCurrentCgroup() (uint64, error) {
	result, err := ebpf.NewMap(&ebpf.MapSpec{Type: ebpf.Array, KeySize: 4, ValueSize: 8, MaxEntries: 1})
	if err != nil {
		return 0, err
	}
	defer result.Close()
	// Socket-filter programs do not expose this helper on the baseline kernel.
	// A tracepoint filtered to this child observes its real syscall context.
	program, err := ebpf.NewProgram(&ebpf.ProgramSpec{Type: ebpf.TracePoint, License: "GPL", Instructions: asm.Instructions{
		asm.FnGetCurrentPidTgid.Call(),
		asm.RSh.Imm(asm.R0, 32),
		asm.JNE.Imm(asm.R0, int32(os.Getpid()), "exit"),
		asm.FnGetCurrentCgroupId.Call(),
		asm.Mov.Reg(asm.R6, asm.R0),
		asm.StoreImm(asm.RFP, -4, 0, asm.Word),
		asm.LoadMapPtr(asm.R1, result.FD()),
		asm.Mov.Reg(asm.R2, asm.RFP),
		asm.Add.Imm(asm.R2, -4),
		asm.FnMapLookupElem.Call(),
		asm.JEq.Imm(asm.R0, 0, "exit"),
		asm.StoreMem(asm.R0, 0, asm.R6, asm.DWord),
		asm.Mov.Imm(asm.R0, 0).WithSymbol("exit"),
		asm.Return(),
	}})
	if err != nil {
		return 0, err
	}
	defer program.Close()
	attachment, err := link.Tracepoint("syscalls", "sys_enter_getpid", program, nil)
	if err != nil {
		return 0, err
	}
	defer attachment.Close()
	if _, _, errno := unix.RawSyscall(unix.SYS_GETPID, 0, 0, 0); errno != 0 {
		return 0, errno
	}
	var identity uint64
	if err := result.Lookup(uint32(0), &identity); err != nil {
		return 0, err
	}
	if identity == 0 {
		return 0, errors.New("BPF scope probe observed zero cgroup ID")
	}
	return identity, nil
}
