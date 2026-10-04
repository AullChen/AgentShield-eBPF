package main

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/agentshield/agentshield-ebpf/internal/inspection"
)

func TestWorkloadSurfaceCannotGrantApprovals(t *testing.T) {
	checker, err := inspection.New(inspection.Config{Routes: []inspection.Route{{ID: "model", Kind: "model"}}, RequestsPerRun: 1, Concurrency: 1}, inspection.Options{
		Authenticate: func(string) (string, error) { return "", errors.New("bad token") }, ActiveRun: func(string) bool { return false }, Audit: func(inspection.Decision) error { return nil },
	}, func(string) ([]byte, error) { return nil, nil })
	if err != nil {
		t.Fatal(err)
	}
	workload := managedWorkloadRoutes(http.NotFoundHandler(), checker)
	for _, path := range []string{"/api/v1/inspection/approvals", "/api/v1/agents/register", "/api/v1/policies", "/gateway/v1/forward"} {
		w := httptest.NewRecorder()
		workload.ServeHTTP(w, httptest.NewRequest("POST", path, strings.NewReader(`{}`)))
		if w.Code != 404 {
			t.Fatal("workload exposed management/forward route")
		}
	}
}

func TestInspectionFileRejectsSymlinkAndOversize(t *testing.T) {
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "config")
	if err := os.WriteFile(path, []byte(`{}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readInspectionFile(path); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(strings.Repeat("x", inspection.MaxBody+1)), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readInspectionFile(path); err == nil {
		t.Fatal("oversized trusted file accepted")
	}
	if _, err := readInspectionFile("relative.json"); err == nil {
		t.Fatal("relative trusted file accepted")
	}
	link := filepath.Join(directory, "link")
	if err := os.Symlink(path, link); err != nil {
		t.Skip("symlink creation not supported by this host")
	}
	if _, err := readInspectionFile(link); err == nil {
		t.Fatal("trusted file symlink accepted")
	}
}
