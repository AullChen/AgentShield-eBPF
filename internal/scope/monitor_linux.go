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
		if handle.root == "" {
			return State{}, fmt.Errorf("held cgroup has no trusted mount root")
		}
		membership, err := unifiedCgroupPath(rootPID)
		if err != nil {
			if !rootPIDExited(err) || !handle.hasFD {
				return State{}, err
			}
			events, openErr := os.Open(filepath.Join(directory, "cgroup.events"))
			if openErr != nil {
				return State{}, fmt.Errorf("open held cgroup.events: %w", openErr)
			}
			defer events.Close()
			empty, readErr := cgroupUnpopulated(events)
			if readErr != nil {
				return State{}, readErr
			}
			if !empty {
				return State{}, err
			}
			state.RootExitedAndEmpty = true
			return state, nil
		}
		state.RootPIDPath = membershipPath(handle.root, strings.TrimPrefix(membership, "/"))
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
