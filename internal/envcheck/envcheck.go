package envcheck

import (
	"context"
	"os"
	"runtime"
	"strings"
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
		fileExistsCheck("btf", "/sys/kernel/btf/vmlinux", "BTF vmlinux is available"),
		cgroupV2Check(),
		bpfPermissionCheck(),
		containerCheck(),
	)
	return report
}

func (r Report) HasFailures() bool {
	for _, check := range r.Checks {
		if check.Status == StatusFail {
			return true
		}
	}
	return false
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

	return Check{
		Name:    "kernel",
		Status:  StatusPass,
		Message: "Linux kernel release detected",
		Details: map[string]string{
			"release": strings.TrimSpace(string(release)),
		},
	}
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
	details := map[string]string{}
	if value, err := os.ReadFile("/proc/sys/kernel/unprivileged_bpf_disabled"); err == nil {
		details["unprivileged_bpf_disabled"] = strings.TrimSpace(string(value))
	}

	if _, err := os.Stat("/sys/fs/bpf"); err != nil {
		details["bpffs_error"] = err.Error()
		return Check{
			Name:    "bpf_permissions",
			Status:  StatusWarn,
			Message: "bpffs is not visible; BPF loading may still work with sufficient privileges",
			Details: details,
		}
	}

	return Check{
		Name:    "bpf_permissions",
		Status:  StatusPass,
		Message: "bpffs is visible; BPF loading still requires runtime privileges",
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
