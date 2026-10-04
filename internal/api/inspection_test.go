package api

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/agentshield/agentshield-ebpf/internal/inspection"
	"github.com/agentshield/agentshield-ebpf/internal/scope"
	"github.com/agentshield/agentshield-ebpf/internal/store"
	"github.com/agentshield/agentshield-ebpf/internal/stream"
)

func TestInspectionUsesSignedRunAndStoresOnlyLocalDecision(t *testing.T) {
	database, err := store.OpenSQLite(filepath.Join(t.TempDir(), "checks.db"), store.SQLiteOptions{})
	if errors.Is(err, store.ErrSQLiteUnavailable) {
		t.Skip(err)
	}
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	hub, err := stream.NewHub(stream.HubOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer hub.Close()
	manager, err := scope.NewManager(&testScopeMap{}, testResolver{ids: map[string]uint64{"/agent/leaf": 42}}, testProbe{})
	if err != nil {
		t.Fatal(err)
	}
	registration, err := NewRegistrationHandler(manager, NewRunStore(), RegistrationOptions{})
	if err != nil {
		t.Fatal(err)
	}
	registered := registerForLifecycleTest(t, registration, "/agent/leaf")
	checker, err := NewInspectionChecker(inspection.Config{Routes: []inspection.Route{{ID: "model", Kind: "model"}}, RequestsPerRun: 4, Concurrency: 2, SensitiveFiles: []string{"known"}}, InspectionOptions{
		Registration: registration, Database: database, Hub: hub, OwnerRead: func(string) ([]byte, error) { return []byte("synthetic-sensitive-value"), nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	body := `{"question":"approved source"}`
	hash := sha256.Sum256([]byte(body))
	if err := checker.Approve(inspection.Approval{RunID: registered.RunID, RouteID: "model", SHA256: hex.EncodeToString(hash[:]), ExpiresAt: time.Now().Add(time.Minute)}); err != nil {
		t.Fatal(err)
	}
	post := func(body, token string) *httptest.ResponseRecorder {
		r := httptest.NewRequest("POST", "/gateway/v1/check/model", strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()
		checker.ServeHTTP(w, r)
		return w
	}
	if post(body, "forged").Code != 401 {
		t.Fatal("forged Run accepted")
	}
	if post(body, registered.IngestToken).Code != 200 {
		t.Fatal("approved check failed")
	}
	if post(`{"content":"synthetic-sensitive-value"}`, registered.IngestToken).Code != 403 {
		t.Fatal("secret accepted")
	}
	provider, err := NewStoredEvidenceProvider(database)
	if err != nil {
		t.Fatal(err)
	}
	timeline, err := provider.Evidence(context.Background(), registered.RunID)
	if err != nil {
		t.Fatal(err)
	}
	if len(timeline.Items) != 3 {
		t.Fatalf("expected synchronous approval/check/deny evidence, got %d", len(timeline.Items))
	}
	for _, item := range timeline.Items {
		if item.Decision == nil || item.Decision.Enforced || item.Decision.Mechanism != "local_preflight_only" || strings.Contains(item.Summary, "synthetic-sensitive") || strings.Contains(item.Summary, registered.IngestToken) {
			t.Fatal("misleading or sensitive evidence")
		}
	}
	if err := database.Close(); err != nil {
		t.Fatal(err)
	}
	if post(body, registered.IngestToken).Code != 503 {
		t.Fatal("failed audit storage did not reject check")
	}
}
