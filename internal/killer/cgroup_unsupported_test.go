//go:build !linux

package killer

import (
	"errors"
	"testing"
)

func TestNewLinuxBackendReportsUnsupportedPlatform(t *testing.T) {
	backend, err := NewLinuxBackend("")
	if backend != nil || !errors.Is(err, ErrUnsupported) {
		t.Fatalf("NewLinuxBackend() = %v, %v; want nil, ErrUnsupported", backend, err)
	}
}
