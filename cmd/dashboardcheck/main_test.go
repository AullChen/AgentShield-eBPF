package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/agentshield/agentshield-ebpf/internal/api"
)

const fixtureToken = "dashboard-fixture-token-123456789"

func TestFixtureServesIntegratedReadOnlyPages(t *testing.T) {
	fixture, err := newFixture(t.Context(), fixtureToken, filepath.Join("..", "..", "configs", "default-policies.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(fixture.handler)
	defer server.Close()
	request, _ := http.NewRequest(http.MethodGet, server.URL+"/api/v1/overview", nil)
	request.Header.Set("Authorization", "Bearer "+fixtureToken)
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	var overview api.OverviewSnapshot
	if err := json.NewDecoder(response.Body).Decode(&overview); err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusOK || len(overview.Runs) != 1 || overview.Runs[0].RunID != fixtureRunID || overview.Counts.Blocked != "1" {
		t.Fatalf("overview = %#v, status = %d", overview, response.StatusCode)
	}

	request, _ = http.NewRequest(http.MethodGet, server.URL+"/api/v1/evidence/"+fixtureRunID, nil)
	request.Header.Set("Authorization", "Bearer "+fixtureToken)
	response, err = http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	var evidenceResponse map[string]any
	if err := json.NewDecoder(response.Body).Decode(&evidenceResponse); err != nil {
		t.Fatal(err)
	}
	items, _ := evidenceResponse["items"].([]any)
	if response.StatusCode != http.StatusOK || len(items) != 6 {
		t.Fatalf("evidence items = %d, status = %d", len(items), response.StatusCode)
	}
}

func TestRequireLoopbackRejectsExposure(t *testing.T) {
	if err := requireLoopback("0.0.0.0:18080"); err == nil {
		t.Fatal("non-loopback fixture listen succeeded")
	}
	if err := requireLoopback("127.0.0.1:18080"); err != nil {
		t.Fatal(err)
	}
}
