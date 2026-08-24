package main

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/agentshield/agentshield-ebpf/internal/api"
)

const liveAPITestToken = "live-api-read-token-123456789"

func TestLiveAPIBridgesAuditLinesToOverview(t *testing.T) {
	tokenFile := filepath.Join(t.TempDir(), "read-token")
	if err := os.WriteFile(tokenFile, []byte(liveAPITestToken+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	live, err := startLiveAPI(ctx, cancel, liveAPIOptions{
		listenAddress: "127.0.0.1:0", readTokenFile: tokenFile, runID: "run-test",
	}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	defer live.close("finished")

	line := `{"schema_version":2,"event_type_name":"exec_attempt","action_name":"audit","action_result_name":"none","server_received_monotonic_ns":"12","server_received_unix_ns":"1800000000000000000"}` + "\n"
	if _, err := live.sink.Write([]byte(line)); err != nil {
		t.Fatal(err)
	}
	request, _ := http.NewRequest(http.MethodGet, "http://"+live.address+"/api/v1/overview", nil)
	request.Header.Set("Authorization", "Bearer "+liveAPITestToken)
	client := &http.Client{Timeout: time.Second}
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("overview status = %d", response.StatusCode)
	}
	var snapshot api.OverviewSnapshot
	if err := json.NewDecoder(response.Body).Decode(&snapshot); err != nil {
		t.Fatal(err)
	}
	if snapshot.Counts.ActiveRuns != "1" || snapshot.Counts.KernelEvents != "1" || len(snapshot.Runs) != 1 {
		t.Fatalf("snapshot = %#v", snapshot)
	}
}

func TestValidateLoopbackListenRejectsExposure(t *testing.T) {
	for _, address := range []string{"0.0.0.0:8080", "192.0.2.1:8080", "localhost:8080", "bad"} {
		if err := validateLoopbackListen(address); err == nil {
			t.Fatalf("validateLoopbackListen(%q) succeeded", address)
		}
	}
	for _, address := range []string{"127.0.0.1:8080", "[::1]:8080"} {
		if err := validateLoopbackListen(address); err != nil {
			t.Fatalf("validateLoopbackListen(%q): %v", address, err)
		}
	}
}
