//go:build linux

package api

import (
	"fmt"
	"net"
	"os"
)

func ListenOwnerUnix(path string) (net.Listener, error) {
	if path == "" {
		return nil, fmt.Errorf("Unix socket path is required")
	}
	listener, err := net.Listen("unix", path)
	if err != nil {
		return nil, fmt.Errorf("listen on management socket: %w", err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		_ = listener.Close()
		return nil, fmt.Errorf("restrict management socket permissions: %w", err)
	}
	return listener, nil
}
