//go:build !linux

package api

import (
	"fmt"
	"net"
)

func ListenOwnerUnix(string) (net.Listener, error) {
	return nil, fmt.Errorf("owner-only Unix management sockets require Linux")
}
