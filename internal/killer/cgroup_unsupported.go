//go:build !linux

package killer

import (
	"fmt"
	"runtime"
)

func NewLinuxBackend(string) (CgroupBackend, error) {
	return nil, fmt.Errorf("%w: cgroup.kill requires Linux, current platform is %s/%s",
		ErrUnsupported, runtime.GOOS, runtime.GOARCH)
}
