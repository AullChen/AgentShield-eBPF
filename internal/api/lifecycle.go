package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"
)

const (
	defaultTombstoneTTL        = 10 * time.Minute
	defaultTombstoneMaxEntries = 10_000
)

var (
	ErrRunNotFound            = errors.New("Agent Run does not exist")
	ErrRunNotLive             = errors.New("Agent Run has no live scope")
	ErrRunTerminationPending  = errors.New("Agent Run termination is already pending")
	ErrScopeIdentityCollision = errors.New("scope identity collides with an active Run or tombstone")
)

type ScopeIdentity struct {
	InstanceID  uint64
	ScopeCookie uint64
}

func (identity ScopeIdentity) Validate() error {
	if identity.InstanceID == 0 || identity.ScopeCookie == 0 {
		return errors.New("instance ID and scope cookie must be non-zero")
	}
	return nil
}

type AttributionStatus string

const (
	AttributionExact   AttributionStatus = "exact"
	AttributionStale   AttributionStatus = "stale"
	AttributionUnknown AttributionStatus = "unknown"
)

type EventAttribution struct {
	RunID     string
	RunStatus string
	Status    AttributionStatus
}

type runTombstone struct {
	RunID     string
	RunStatus string
	ExpiresAt time.Time
	sequence  uint64
}

type FinishResponse struct {
	RunID   string `json:"run_id"`
	Status  string `json:"status"`
	EndedAt string `json:"ended_at"`
}

func (run AgentRun) scopeIdentity() ScopeIdentity {
	return ScopeIdentity{InstanceID: run.InstanceID, ScopeCookie: run.ScopeCookie}
}

func (store *RunStore) beginTermination(runID string) (AgentRun, bool, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	run, exists := store.runs[runID]
	if !exists {
		return AgentRun{}, false, ErrRunNotFound
	}
	if !run.EndedAt.IsZero() {
		run.Labels = cloneLabels(run.Labels)
		return run, false, nil
	}
	if _, pending := store.terminating[runID]; pending {
		return AgentRun{}, false, ErrRunTerminationPending
	}
	if liveRunID, live := store.liveByIdentity[run.scopeIdentity()]; !live || liveRunID != runID {
		return AgentRun{}, false, ErrRunNotLive
	}
	store.terminating[runID] = struct{}{}
	run.Labels = cloneLabels(run.Labels)
	return run, true, nil
}

func (store *RunStore) abortTermination(runID string) {
	store.mu.Lock()
	defer store.mu.Unlock()
	delete(store.terminating, runID)
}

func (store *RunStore) completeTermination(runID, terminalStatus string, endedAt time.Time, ttl time.Duration, maxEntries int) (AgentRun, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	run, exists := store.runs[runID]
	if !exists {
		return AgentRun{}, ErrRunNotFound
	}
	if _, pending := store.terminating[runID]; !pending {
		return AgentRun{}, ErrRunTerminationPending
	}

	identity := run.scopeIdentity()
	if terminalStatus == "expired" || run.Status == "active" {
		run.Status = terminalStatus
	}
	run.EndedAt = endedAt.UTC()
	store.runs[runID] = run
	delete(store.terminating, runID)
	if activeRunID, active := store.activeByCgroup[run.CgroupID]; active && activeRunID == runID {
		delete(store.activeByCgroup, run.CgroupID)
	}
	delete(store.liveByIdentity, identity)

	store.pruneTombstonesLocked(endedAt)
	for len(store.tombstones) >= maxEntries {
		store.evictOldestTombstoneLocked()
	}
	store.tombstoneSeq++
	store.tombstones[identity] = runTombstone{
		RunID:     runID,
		RunStatus: run.Status,
		ExpiresAt: endedAt.Add(ttl),
		sequence:  store.tombstoneSeq,
	}
	run.Labels = cloneLabels(run.Labels)
	return run, nil
}

func (store *RunStore) expiredActiveRunIDs(now time.Time) []string {
	store.mu.RLock()
	defer store.mu.RUnlock()
	runIDs := make([]string, 0)
	for runID, run := range store.runs {
		if run.Status == "active" && !run.RunExpiry.IsZero() && !now.Before(run.RunExpiry) {
			runIDs = append(runIDs, runID)
		}
	}
	return runIDs
}

func (store *RunStore) attribute(identity ScopeIdentity, currentInstanceID uint64, now time.Time) EventAttribution {
	store.mu.Lock()
	defer store.mu.Unlock()
	store.pruneTombstonesLocked(now)
	if runID, exists := store.liveByIdentity[identity]; exists {
		run := store.runs[runID]
		return EventAttribution{RunID: runID, RunStatus: run.Status, Status: AttributionExact}
	}
	if tombstone, exists := store.tombstones[identity]; exists {
		return EventAttribution{
			RunID:     tombstone.RunID,
			RunStatus: tombstone.RunStatus,
			Status:    AttributionExact,
		}
	}
	if identity.InstanceID == currentInstanceID && currentInstanceID != 0 {
		return EventAttribution{Status: AttributionStale}
	}
	return EventAttribution{Status: AttributionUnknown}
}

func (store *RunStore) pruneTombstonesLocked(now time.Time) {
	if now.IsZero() {
		return
	}
	for identity, tombstone := range store.tombstones {
		if !now.Before(tombstone.ExpiresAt) {
			delete(store.tombstones, identity)
		}
	}
}

func (store *RunStore) evictOldestTombstoneLocked() {
	var (
		oldestIdentity ScopeIdentity
		oldestSequence uint64
		found          bool
	)
	for identity, tombstone := range store.tombstones {
		if !found || tombstone.sequence < oldestSequence {
			oldestIdentity = identity
			oldestSequence = tombstone.sequence
			found = true
		}
	}
	if found {
		delete(store.tombstones, oldestIdentity)
	}
}

func (handler *RegistrationHandler) FinishRun(runID string) (AgentRun, error) {
	return handler.terminateRun(strings.TrimSpace(runID), "finished", handler.now().UTC())
}

func (handler *RegistrationHandler) CleanupExpiredRuns() error {
	now := handler.now().UTC()
	var cleanupErrors []error
	for _, runID := range handler.store.expiredActiveRunIDs(now) {
		if _, err := handler.terminateRun(runID, "expired", now); err != nil {
			cleanupErrors = append(cleanupErrors, fmt.Errorf("expire Run %s: %w", runID, err))
		}
	}
	handler.store.mu.Lock()
	handler.store.pruneTombstonesLocked(now)
	handler.store.mu.Unlock()
	return errors.Join(cleanupErrors...)
}

func (handler *RegistrationHandler) AttributeEvent(instanceID, scopeCookie uint64) EventAttribution {
	return handler.store.attribute(
		ScopeIdentity{InstanceID: instanceID, ScopeCookie: scopeCookie},
		handler.instanceID,
		handler.now().UTC(),
	)
}

func (handler *RegistrationHandler) terminateRun(runID, status string, endedAt time.Time) (AgentRun, error) {
	run, unregister, err := handler.store.beginTermination(runID)
	if err != nil || !unregister {
		return run, err
	}
	if err := handler.registrar.Unregister(run.CgroupID); err != nil {
		handler.store.abortTermination(runID)
		return AgentRun{}, fmt.Errorf("remove cgroup scope: %w", err)
	}
	finished, err := handler.store.completeTermination(
		runID,
		status,
		endedAt,
		handler.tombstoneTTL,
		handler.tombstoneMaxEntries,
	)
	if err != nil {
		return AgentRun{}, fmt.Errorf("complete Run termination: %w", err)
	}
	return finished, nil
}

func (handler *RegistrationHandler) serveFinish(response http.ResponseWriter, request *http.Request) {
	run, err := handler.FinishRun(request.PathValue("run_id"))
	if err != nil {
		status := http.StatusConflict
		if errors.Is(err, ErrRunNotFound) {
			status = http.StatusNotFound
		}
		http.Error(response, http.StatusText(status), status)
		return
	}
	response.Header().Set("Content-Type", "application/json")
	response.Header().Set("Cache-Control", "no-store")
	_ = writeJSON(response, http.StatusOK, FinishResponse{
		RunID:   run.RunID,
		Status:  run.Status,
		EndedAt: run.EndedAt.Format(time.RFC3339Nano),
	})
}

func writeJSON(response http.ResponseWriter, status int, value any) error {
	response.WriteHeader(status)
	return json.NewEncoder(response).Encode(value)
}
