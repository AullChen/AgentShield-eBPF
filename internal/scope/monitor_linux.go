//go:build linux

package scope

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

type LinuxInspector struct{}

func (LinuxInspector) Inspect(handle *Handle, rootPID int) (State, error) {
	directory := handle.Path
	if handle.hasFD {
		directory = filepath.Join("/proc/self/fd", strconv.Itoa(handle.fd))
	}
	entries, err := os.ReadDir(directory)
	if err != nil {
		return State{}, fmt.Errorf("read held cgroup directory: %w", err)
	}
	state := State{}
	for _, entry := range entries {
		if entry.IsDir() {
			state.ChildCgroups = append(state.ChildCgroups, filepath.Join(handle.Path, entry.Name()))
		}
	}
	if rootPID > 0 {
		membership, err := unifiedCgroupPath(rootPID)
		if err != nil {
			return State{}, err
		}
		state.RootPIDPath = filepath.Join(defaultCgroupRoot, strings.TrimPrefix(membership, "/"))
	}
	return state, nil
}

func unifiedCgroupPath(pid int) (string, error) {
	file, err := os.Open(filepath.Join("/proc", strconv.Itoa(pid), "cgroup"))
	if err != nil {
		return "", fmt.Errorf("open PID cgroup membership: %w", err)
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		hierarchy, membership, ok := strings.Cut(scanner.Text(), "::")
		if ok && hierarchy == "0" {
			return membership, nil
		}
	}
	if err := scanner.Err(); err != nil {
		return "", fmt.Errorf("read PID cgroup membership: %w", err)
	}
	return "", fmt.Errorf("PID has no unified cgroup v2 membership")
}
