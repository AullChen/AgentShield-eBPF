package envcheck

import (
	"context"
	"errors"
	"runtime"
	"testing"
)

func TestRunReturnsReport(t *testing.T) {
	report := Run(context.Background())
	if report.OS != runtime.GOOS {
		t.Fatalf("OS = %q, want %q", report.OS, runtime.GOOS)
	}
	if report.Arch != runtime.GOARCH {
		t.Fatalf("Arch = %q, want %q", report.Arch, runtime.GOARCH)
	}
	if len(report.Checks) == 0 {
		t.Fatal("Run returned no checks")
	}
}

func TestReportHasFailures(t *testing.T) {
	report := Report{
		Checks: []Check{
			{Name: "pass", Status: StatusPass},
			{Name: "warn", Status: StatusWarn},
		},
	}
	if report.HasFailures() {
		t.Fatal("HasFailures returned true without failures")
	}

	report.Checks = append(report.Checks, Check{Name: "fail", Status: StatusFail})
	if !report.HasFailures() {
		t.Fatal("HasFailures returned false with a failure")
	}
}

func TestReportIsReadyRequiresConclusiveChecks(t *testing.T) {
	if (Report{}).IsReady() {
		t.Fatal("IsReady returned true for an empty report")
	}

	ready := Report{Checks: []Check{
		{Name: "pass", Status: StatusPass},
		{Name: "warn", Status: StatusWarn},
	}}
	if !ready.IsReady() {
		t.Fatal("IsReady returned false for pass/warn checks")
	}

	for _, status := range []Status{StatusUnknown, StatusFail} {
		report := Report{Checks: []Check{{Name: "required", Status: status}}}
		if report.IsReady() {
			t.Fatalf("IsReady returned true for %q check", status)
		}
	}
}

func TestArchitectureCheck(t *testing.T) {
	tests := []struct {
		name   string
		goos   string
		goarch string
		status Status
	}{
		{name: "linux amd64", goos: "linux", goarch: "amd64", status: StatusPass},
		{name: "linux arm64", goos: "linux", goarch: "arm64", status: StatusPass},
		{name: "linux 386", goos: "linux", goarch: "386", status: StatusFail},
		{name: "linux big endian", goos: "linux", goarch: "s390x", status: StatusFail},
		{name: "non linux", goos: "windows", goarch: "amd64", status: StatusUnknown},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			check := architectureCheck(test.goos, test.goarch)
			if check.Status != test.status {
				t.Fatalf("architectureCheck(%q, %q).Status = %q, want %q", test.goos, test.goarch, check.Status, test.status)
			}
			if check.Details["arch"] != test.goarch {
				t.Fatalf("arch detail = %q, want %q", check.Details["arch"], test.goarch)
			}
		})
	}
}

func TestKernelReleaseCheck(t *testing.T) {
	tests := []struct {
		name    string
		release string
		status  Status
	}{
		{name: "minimum", release: "5.15.0-1092-azure", status: StatusPass},
		{name: "newer minor", release: "5.16.0", status: StatusPass},
		{name: "newer major", release: "6.1.0", status: StatusPass},
		{name: "older minor", release: "5.14.21", status: StatusFail},
		{name: "older major", release: "4.19.0", status: StatusFail},
		{name: "missing minor", release: "6", status: StatusUnknown},
		{name: "non numeric", release: "linux-current", status: StatusUnknown},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			check := kernelReleaseCheck(test.release)
			if check.Status != test.status {
				t.Fatalf("kernelReleaseCheck(%q).Status = %q, want %q", test.release, check.Status, test.status)
			}
			if check.Details["release"] != test.release {
				t.Fatalf("release detail = %q, want %q", check.Details["release"], test.release)
			}
			if check.Details["minimum"] != "5.15" {
				t.Fatalf("minimum detail = %q, want 5.15", check.Details["minimum"])
			}
		})
	}
}

func TestBPFPermissionResultDoesNotClaimUnprobedPermission(t *testing.T) {
	visible := bpfPermissionResult("2", nil)
	if visible.Status != StatusUnknown {
		t.Fatalf("visible bpffs status = %q, want %q", visible.Status, StatusUnknown)
	}
	if visible.Details["bpffs"] != "visible" {
		t.Fatalf("bpffs detail = %q, want visible", visible.Details["bpffs"])
	}
	if visible.Details["permission_probe"] != "not_performed" {
		t.Fatalf("permission_probe detail = %q, want not_performed", visible.Details["permission_probe"])
	}

	notVisible := bpfPermissionResult("", errors.New("not mounted"))
	if notVisible.Status != StatusUnknown {
		t.Fatalf("missing bpffs status = %q, want %q", notVisible.Status, StatusUnknown)
	}
	if notVisible.Details["bpffs"] != "not_visible" {
		t.Fatalf("bpffs detail = %q, want not_visible", notVisible.Details["bpffs"])
	}
}
