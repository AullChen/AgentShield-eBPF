package envcheck

import (
	"context"
	"fmt"
	"os"
	"runtime"
	"strconv"
	"strings"
)

const (
	minimumKernelMajor = 5
	minimumKernelMinor = 15
)

type Status string

const (
	StatusPass    Status = "pass"
	StatusWarn    Status = "warn"
	StatusFail    Status = "fail"
	StatusUnknown Status = "unknown"
)

type Check struct {
	Name    string            `json:"name"`
	Status  Status            `json:"status"`
	Message string            `json:"message"`
	Details map[string]string `json:"details,omitempty"`
}

type Report struct {
	OS     string  `json:"os"`
	Arch   string  `json:"arch"`
	Checks []Check `json:"checks"`
}

func Run(ctx context.Context) Report {
	report := Report{
		OS:   runtime.GOOS,
		Arch: runtime.GOARCH,
	}

	if runtime.GOOS != "linux" {
		report.Checks = append(report.Checks,
			Check{
				Name:    "linux",
				Status:  StatusFail,
				Message: "AgentShield kernel features require Linux",
				Details: map[string]string{
					"current_os": runtime.GOOS,
				},
			},
			architectureCheck(runtime.GOOS, runtime.GOARCH),
			Check{
				Name:    "btf",
				Status:  StatusUnknown,
				Message: "BTF detection is only available on Linux",
			},
			Check{
				Name:    "cgroup_v2",
				Status:  StatusUnknown,
				Message: "cgroup v2 detection is only available on Linux",
			},
			Check{
				Name:    "bpf_permissions",
				Status:  StatusUnknown,
				Message: "BPF permission detection is only available on Linux",
			},
			Check{
				Name:    "container",
				Status:  StatusUnknown,
				Message: "container environment detection is only available on Linux",
			},
		)
		return report
	}

	select {
	case <-ctx.Done():
		report.Checks = append(report.Checks, Check{
			Name:    "context",
			Status:  StatusFail,
			Message: ctx.Err().Error(),
		})
		return report
	default:
	}

	report.Checks = append(report.Checks,
		linuxKernelCheck(),
		architectureCheck(runtime.GOOS, runtime.GOARCH),
		fileExistsCheck("btf", "/sys/kernel/btf/vmlinux", "BTF vmlinux is available"),
		cgroupV2Check(),
		bpfPermissionCheck(),
		containerCheck(),
	)
	return report
}

func architectureCheck(goos string, goarch string) Check {
	details := map[string]string{
		"os":                     goos,
		"arch":                   goarch,
		"supported_linux_arches": "amd64,arm64",
	}
	if goos != "linux" {
		return Check{
			Name:    "architecture",
			Status:  StatusUnknown,
			Message: "architecture support is only evaluated on Linux",
			Details: details,
		}
	}

	switch goarch {
	case "amd64", "arm64":
		return Check{
			Name:    "architecture",
			Status:  StatusPass,
			Message: "architecture is supported",
			Details: details,
		}
	default:
		return Check{
			Name:    "architecture",
			Status:  StatusFail,
			Message: "architecture is not supported by the current kernel event decoder",
			Details: details,
		}
	}
}

func (r Report) HasFailures() bool {
	for _, check := range r.Checks {
		if check.Status == StatusFail {
			return true
		}
	}
	return false
}

// IsReady reports whether every required capability was conclusively checked.
// Warnings are informational, while unknown and failed checks both prevent a
// successful readiness result.
func (r Report) IsReady() bool {
	if len(r.Checks) == 0 {
		return false
	}
	for _, check := range r.Checks {
		if check.Status == StatusFail || check.Status == StatusUnknown {
			return false
		}
	}
	return true
}

func linuxKernelCheck() Check {
	release, err := os.ReadFile("/proc/sys/kernel/osrelease")
	if err != nil {
		return Check{
			Name:    "kernel",
			Status:  StatusUnknown,
			Message: "unable to read Linux kernel release",
			Details: map[string]string{
				"error": err.Error(),
			},
		}
	}
	return kernelReleaseCheck(string(release))
}

func kernelReleaseCheck(release string) Check {
	release = strings.TrimSpace(release)
	details := map[string]string{
		"release": release,
		"minimum": fmt.Sprintf("%d.%d", minimumKernelMajor, minimumKernelMinor),
	}

	major, minor, err := parseKernelVersion(release)
	if err != nil {
		details["error"] = err.Error()
		return Check{
			Name:    "kernel",
			Status:  StatusUnknown,
			Message: "unable to determine whether the Linux kernel version is supported",
			Details: details,
		}
	}
	if major < minimumKernelMajor || major == minimumKernelMajor && minor < minimumKernelMinor {
		return Check{
			Name:    "kernel",
			Status:  StatusFail,
			Message: "Linux kernel is older than the minimum supported version",
			Details: details,
		}
	}

	return Check{
		Name:    "kernel",
		Status:  StatusPass,
		Message: "Linux kernel version is supported",
		Details: details,
	}
}

func parseKernelVersion(release string) (int, int, error) {
	parts := strings.Split(strings.TrimSpace(release), ".")
	if len(parts) < 2 || parts[0] == "" || parts[1] == "" {
		return 0, 0, fmt.Errorf("invalid kernel release %q", release)
	}

	major, err := strconv.Atoi(parts[0])
	if err != nil || major < 0 {
		return 0, 0, fmt.Errorf("invalid kernel major version in %q", release)
	}
	minor, err := strconv.Atoi(parts[1])
	if err != nil || minor < 0 {
		return 0, 0, fmt.Errorf("invalid kernel minor version in %q", release)
	}
	return major, minor, nil
}

func fileExistsCheck(name string, path string, message string) Check {
	if _, err := os.Stat(path); err != nil {
		return Check{
			Name:    name,
			Status:  StatusFail,
			Message: "required file is not available",
			Details: map[string]string{
				"path":  path,
				"error": err.Error(),
			},
		}
	}

	return Check{
		Name:    name,
		Status:  StatusPass,
		Message: message,
		Details: map[string]string{
			"path": path,
		},
	}
}

func cgroupV2Check() Check {
	const path = "/sys/fs/cgroup/cgroup.controllers"
	contents, err := os.ReadFile(path)
	if err != nil {
		return Check{
			Name:    "cgroup_v2",
			Status:  StatusFail,
			Message: "cgroup v2 controllers file is not available",
			Details: map[string]string{
				"path":  path,
				"error": err.Error(),
			},
		}
	}

	return Check{
		Name:    "cgroup_v2",
		Status:  StatusPass,
		Message: "cgroup v2 is available",
		Details: map[string]string{
			"controllers": strings.TrimSpace(string(contents)),
		},
	}
}

func bpfPermissionCheck() Check {
	unprivilegedBPFDisabled := ""
	if value, err := os.ReadFile("/proc/sys/kernel/unprivileged_bpf_disabled"); err == nil {
		unprivilegedBPFDisabled = strings.TrimSpace(string(value))
	}

	_, bpffsErr := os.Stat("/sys/fs/bpf")
	return bpfPermissionResult(unprivilegedBPFDisabled, bpffsErr)
}

func bpfPermissionResult(unprivilegedBPFDisabled string, bpffsErr error) Check {
	details := map[string]string{
		"permission_probe": "not_performed",
	}
	if unprivilegedBPFDisabled != "" {
		details["unprivileged_bpf_disabled"] = unprivilegedBPFDisabled
	}

	if bpffsErr != nil {
		details["bpffs"] = "not_visible"
		details["bpffs_error"] = bpffsErr.Error()
		return Check{
			Name:    "bpf_permissions",
			Status:  StatusUnknown,
			Message: "bpffs is not visible and BPF loading permission was not probed",
			Details: details,
		}
	}

	details["bpffs"] = "visible"
	return Check{
		Name:    "bpf_permissions",
		Status:  StatusUnknown,
		Message: "bpffs is visible, but BPF loading permission was not probed",
		Details: details,
	}
}

func containerCheck() Check {
	details := map[string]string{}
	if _, err := os.Stat("/.dockerenv"); err == nil {
		details["runtime"] = "docker"
		return Check{
			Name:    "container",
			Status:  StatusWarn,
			Message: "process appears to run inside Docker",
			Details: details,
		}
	}
	if _, err := os.Stat("/run/.containerenv"); err == nil {
		details["runtime"] = "container"
		return Check{
			Name:    "container",
			Status:  StatusWarn,
			Message: "process appears to run inside a container",
			Details: details,
		}
	}

	version, err := os.ReadFile("/proc/version")
	if err == nil && strings.Contains(strings.ToLower(string(version)), "microsoft") {
		details["runtime"] = "wsl"
		return Check{
			Name:    "container",
			Status:  StatusWarn,
			Message: "process appears to run inside WSL",
			Details: details,
		}
	}

	return Check{
		Name:    "container",
		Status:  StatusPass,
		Message: "no common container or WSL marker detected",
	}
}
