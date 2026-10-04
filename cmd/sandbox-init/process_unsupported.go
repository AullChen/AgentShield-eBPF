//go:build !linux

package main

import (
	"errors"
	"os/exec"
)

func prepare() error                     { return errors.New("sandbox-init requires Linux") }
func configureProcess(command *exec.Cmd) {}
