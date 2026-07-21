//go:build !linux

package scope

import (
	"fmt"
	"runtime"
)

type LinuxResolver struct{}

func NewLinuxResolver(string) (*LinuxResolver, error) {
	return nil, fmt.Errorf("trusted cgroup resolution requires Linux, current platform is %s/%s", runtime.GOOS, runtime.GOARCH)
}

func (*LinuxResolver) ResolvePath(string) (*Handle, error) {
	return nil, fmt.Errorf("trusted cgroup resolution requires Linux")
}

func (*LinuxResolver) ResolvePID(int) (*Handle, error) {
	return nil, fmt.Errorf("trusted cgroup resolution requires Linux")
}
