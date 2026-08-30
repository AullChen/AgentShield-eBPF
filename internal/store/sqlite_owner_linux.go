//go:build linux

package store

import (
	"errors"
	"os"
	"syscall"
)

func validateSQLiteDirectoryOwner(info os.FileInfo) error {
	if info.Mode().Perm()&0o077 != 0 {
		return errors.New("SQLite directory must not be accessible by group or other users")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != uint32(os.Geteuid()) {
		return errors.New("SQLite directory owner does not match the effective user")
	}
	return nil
}
