//go:build !linux

package api

import (
	"fmt"
	"net"
)

func ListenOwnerUnix(string) (net.Listener, error) {
	return nil, fmt.Errorf("owner-only Unix management sockets require Linux")
}

func ListenWorkloadUnix(string) (net.Listener, error) {
	return nil, fmt.Errorf("workload Unix sockets require Linux")
}
