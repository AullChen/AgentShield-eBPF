package api

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"math"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

var (
	ErrOverviewRunNotFound = errors.New("overview run not found")
	ErrOverviewOverflow    = errors.New("overview counter overflow")
)

type OverviewCounts struct {
	ActiveRuns   string `json:"active_runs"`
	KernelEvents string `json:"kernel_events"`
	PolicyHits   string `json:"policy_hits"`
	Blocked      string `json:"blocked"`
}

type OverviewRun struct {
	RunID        string `json:"run_id"`
	Label        string `json:"label"`
	Status       string `json:"status"`
	StartedAt    string `json:"started_at"`
	LastEventAt  string `json:"last_event_at,omitempty"`
	EventCount   string `json:"event_count"`
	BlockedCount string `json:"blocked_count"`
}

type OverviewCapability struct {
	Name   string `json:"name"`
	Status string `json:"status"`
	Detail string `json:"detail"`
}

type OverviewSnapshot struct {
	SchemaVersion string               `json:"schema_version"`
	GeneratedAt   string               `json:"generated_at"`
	Counts        OverviewCounts       `json:"counts"`
	Runs          []OverviewRun        `json:"runs"`
	Capabilities  []OverviewCapability `json:"capabilities"`
}

type OverviewProvider interface {
	Overview(context.Context) (OverviewSnapshot, error)
}

type OverviewState struct {
	mu           sync.RWMutex
	now          func() time.Time
	runs         map[string]overviewRunState
	kernelEvents uint64
	policyHits   uint64
	blocked      uint64
	capabilities []OverviewCapability
}

type overviewRunState struct {
	runID        string
	label        string
	status       string
	startedAt    time.Time
	lastEventAt  time.Time
	eventCount   uint64
	blockedCount uint64
}

type OverviewStateOptions struct {
	Now func() time.Time
}

type OverviewRunInput struct {
	RunID     string
	Label     string
	Status    string
	StartedAt time.Time
}

type OverviewEventInput struct {
	RunID      string
	PolicyHit  bool
	Blocked    bool
	OccurredAt time.Time
}

func NewOverviewState(options OverviewStateOptions) *OverviewState {
	if options.Now == nil {
		options.Now = time.Now
	}
	return &OverviewState{now: options.Now, runs: make(map[string]overviewRunState)}
}

func (state *OverviewState) UpsertRun(input OverviewRunInput) error {
	if input.RunID == "" || len(input.RunID) > 128 || len(input.Label) > 128 ||
		!validRunStatus(input.Status) || input.StartedAt.IsZero() {
		return errors.New("invalid overview run")
	}
	state.mu.Lock()
	defer state.mu.Unlock()
	run := state.runs[input.RunID]
	run.runID = input.RunID
	run.label = input.Label
	run.status = input.Status
	run.startedAt = input.StartedAt
	state.runs[input.RunID] = run
	return nil
}

func (state *OverviewState) ObserveEvent(input OverviewEventInput) error {
	state.mu.Lock()
	defer state.mu.Unlock()
	run, exists := state.runs[input.RunID]
	if !exists {
		return ErrOverviewRunNotFound
	}
	if state.kernelEvents == math.MaxUint64 || run.eventCount == math.MaxUint64 ||
		(input.PolicyHit && state.policyHits == math.MaxUint64) ||
		(input.Blocked && (state.blocked == math.MaxUint64 || run.blockedCount == math.MaxUint64)) {
		return ErrOverviewOverflow
	}
	state.kernelEvents++
	run.eventCount++
	if input.PolicyHit {
		state.policyHits++
	}
	if input.Blocked {
		state.blocked++
		run.blockedCount++
	}
	if input.OccurredAt.IsZero() {
		input.OccurredAt = state.now()
	}
	if input.OccurredAt.After(run.lastEventAt) {
		run.lastEventAt = input.OccurredAt
	}
	state.runs[input.RunID] = run
	return nil
}

func (state *OverviewState) ObservePolicyHit(runID string) error {
	state.mu.Lock()
	defer state.mu.Unlock()
	if _, exists := state.runs[runID]; !exists {
		return ErrOverviewRunNotFound
	}
	if state.policyHits == math.MaxUint64 {
		return ErrOverviewOverflow
	}
	state.policyHits++
	return nil
}

func (state *OverviewState) SetCapabilities(capabilities []OverviewCapability) error {
	seen := make(map[string]struct{}, len(capabilities))
	copyOf := make([]OverviewCapability, len(capabilities))
	for index, capability := range capabilities {
		if capability.Name == "" || len(capability.Name) > 64 || len(capability.Detail) > 256 ||
			!validCapabilityStatus(capability.Status) {
			return errors.New("invalid overview capability")
		}
		if _, exists := seen[capability.Name]; exists {
			return errors.New("duplicate overview capability")
		}
		seen[capability.Name] = struct{}{}
		copyOf[index] = capability
	}
	sort.Slice(copyOf, func(left, right int) bool { return copyOf[left].Name < copyOf[right].Name })
	state.mu.Lock()
	state.capabilities = copyOf
	state.mu.Unlock()
	return nil
}

func (state *OverviewState) Overview(context.Context) (OverviewSnapshot, error) {
	state.mu.RLock()
	defer state.mu.RUnlock()
	runs := make([]OverviewRun, 0, len(state.runs))
	active := uint64(0)
	for _, run := range state.runs {
		if run.status == "active" {
			active++
		}
		lastEventAt := ""
		if !run.lastEventAt.IsZero() {
			lastEventAt = run.lastEventAt.UTC().Format(time.RFC3339Nano)
		}
		runs = append(runs, OverviewRun{
			RunID: run.runID, Label: run.label, Status: run.status,
			StartedAt: run.startedAt.UTC().Format(time.RFC3339Nano), LastEventAt: lastEventAt,
			EventCount: strconv.FormatUint(run.eventCount, 10), BlockedCount: strconv.FormatUint(run.blockedCount, 10),
		})
	}
	sort.Slice(runs, func(left, right int) bool {
		if runs[left].Status != runs[right].Status {
			return runStatusRank(runs[left].Status) < runStatusRank(runs[right].Status)
		}
		if runs[left].StartedAt != runs[right].StartedAt {
			return runs[left].StartedAt > runs[right].StartedAt
		}
		return runs[left].RunID < runs[right].RunID
	})
	capabilities := append([]OverviewCapability(nil), state.capabilities...)
	return OverviewSnapshot{
		SchemaVersion: "1",
		GeneratedAt:   state.now().UTC().Format(time.RFC3339Nano),
		Counts: OverviewCounts{
			ActiveRuns: strconv.FormatUint(active, 10), KernelEvents: strconv.FormatUint(state.kernelEvents, 10),
			PolicyHits: strconv.FormatUint(state.policyHits, 10), Blocked: strconv.FormatUint(state.blocked, 10),
		},
		Runs: runs, Capabilities: capabilities,
	}, nil
}

func validRunStatus(status string) bool {
	return status == "active" || status == "finished" || status == "failed"
}

func runStatusRank(status string) int {
	switch status {
	case "active":
		return 0
	case "failed":
		return 1
	default:
		return 2
	}
}

func validCapabilityStatus(status string) bool {
	return status == "available" || status == "degraded" || status == "unavailable" || status == "unknown"
}

type OverviewHandlerOptions struct {
	ReadToken string
}

type OverviewHandler struct {
	provider  OverviewProvider
	tokenHash [sha256.Size]byte
}

func NewOverviewHandler(provider OverviewProvider, options OverviewHandlerOptions) (*OverviewHandler, error) {
	if provider == nil || len(options.ReadToken) < 24 || len(options.ReadToken) > 512 {
		return nil, errors.New("overview requires a provider and a 24-512 byte read token")
	}
	return &OverviewHandler{provider: provider, tokenHash: sha256.Sum256([]byte(options.ReadToken))}, nil
}

func (handler *OverviewHandler) Routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/v1/overview", handler.ServeHTTP)
	return mux
}

func (handler *OverviewHandler) ServeHTTP(response http.ResponseWriter, request *http.Request) {
	if !handler.authorized(request.Header.Get("Authorization")) {
		response.Header().Set("WWW-Authenticate", "Bearer")
		http.Error(response, "unauthorized", http.StatusUnauthorized)
		return
	}
	snapshot, err := handler.provider.Overview(request.Context())
	if err != nil {
		http.Error(response, "overview unavailable", http.StatusServiceUnavailable)
		return
	}
	response.Header().Set("Cache-Control", "no-store")
	response.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(response).Encode(snapshot)
}

func (handler *OverviewHandler) authorized(header string) bool {
	scheme, token, ok := strings.Cut(header, " ")
	if !ok || !strings.EqualFold(scheme, "Bearer") || token == "" || len(token) > 512 || strings.ContainsAny(token, " \t\r\n") {
		return false
	}
	digest := sha256.Sum256([]byte(token))
	return subtle.ConstantTimeCompare(digest[:], handler.tokenHash[:]) == 1
}
