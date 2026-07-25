//go:build linux

package api

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"syscall"
)

func ListenOwnerUnix(path string) (net.Listener, error) {
	if path == "" {
		return nil, fmt.Errorf("Unix socket path is required")
	}
	absolutePath, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("resolve management socket path: %w", err)
	}
	parent := filepath.Dir(absolutePath)
	resolvedParent, err := filepath.EvalSymlinks(parent)
	if err != nil {
		return nil, fmt.Errorf("resolve management socket directory: %w", err)
	}
	if resolvedParent != parent {
		return nil, fmt.Errorf("management socket directory must not contain symbolic links")
	}
	info, err := os.Stat(parent)
	if err != nil {
		return nil, fmt.Errorf("stat management socket directory: %w", err)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return nil, fmt.Errorf("read management socket directory ownership")
	}
	if err := validateSocketDirectory(info.Mode(), stat.Uid, uint32(os.Geteuid())); err != nil {
		return nil, err
	}

	listener, err := net.Listen("unix", absolutePath)
	if err != nil {
		return nil, fmt.Errorf("listen on management socket: %w", err)
	}
	if err := os.Chmod(absolutePath, 0o600); err != nil {
		_ = listener.Close()
		return nil, fmt.Errorf("restrict management socket permissions: %w", err)
	}
	return listener, nil
}
