package envcheck

import (
	"context"
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
