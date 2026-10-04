//go:build linux

package main

import (
	"errors"
	"os"
	"os/exec"
	"syscall"
)

func prepare() error {
	if os.Getpid() != 1 || os.Geteuid() != 65532 {
		return errors.New("requires the unprivileged container PID 1")
	}
	// The host also sends SIGSTOP from the ancestor PID namespace and verifies
	// every thread is stopped; PID-namespace init signal rules vary. Until the
	// host registers the held leaf, stdin remains empty and no workload starts.
	if _, err := os.Stdout.WriteString("agentshield-init-ready\n"); err != nil {
		return err
	}
	return syscall.Kill(1, syscall.SIGSTOP)
}

func configureProcess(command *exec.Cmd) {
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	command.Cancel = func() error {
		return syscall.Kill(-command.Process.Pid, syscall.SIGKILL)
	}
}
