//go:build !linux

package scope

import "fmt"

type LinuxInspector struct{}

func (LinuxInspector) Inspect(*Handle, int) (State, error) {
	return State{}, fmt.Errorf("cgroup scope inspection requires Linux")
}
