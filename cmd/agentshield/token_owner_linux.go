//go:build linux

package main

import (
	"errors"
	"os"
	"syscall"
)

func validateReadTokenOwner(info os.FileInfo) error {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return errors.New("could not determine read token file owner")
	}
	if stat.Uid != uint32(os.Geteuid()) {
		return errors.New("read token file owner does not match the effective user")
	}
	return nil
}
