package api

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/agentshield/agentshield-ebpf/internal/scope"
)

const (
	RegisterPath    = "/api/v1/agents/register"
	defaultTokenTTL = 15 * time.Minute
	maxRequestBytes = 64 << 10
	maxTokenBytes   = 512
)

type Registrar interface {
	Register(context.Context, scope.Target, scope.Value) (scope.Registration, error)
	Unregister(cgroupID uint64) error
}

type RegisterRequest struct {
	AgentName   string            `json:"agent_name"`
	ContainerID string            `json:"container_id,omitempty"`
	CgroupPath  string            `json:"cgroup_path,omitempty"`
	PID         int               `json:"pid,omitempty"`
	RootPID     int               `json:"root_pid,omitempty"`
	ProfileID   uint32            `json:"profile_id,omitempty"`
	ScopeMode   string            `json:"scope_mode,omitempty"`
	Labels      map[string]string `json:"labels,omitempty"`
}

type RegisterResponse struct {
	RunID       string `json:"run_id"`
	CgroupID    string `json:"cgroup_id"`
	InstanceID  string `json:"instance_id"`
	ScopeCookie string `json:"scope_cookie"`
	CgroupPath  string `json:"cgroup_path"`
	ScopeMode   string `json:"scope_mode"`
	IngestToken string `json:"ingest_token"`
	TokenExpiry string `json:"token_expiry"`
}

type AgentRun struct {
	RunID        string
	AgentName    string
	ContainerID  string
	CgroupID     uint64
	InstanceID   uint64
	ScopeCookie  uint64
	CgroupPath   string
	ScopeMode    string
	RootPID      int
	ProfileID    uint32
	Labels       map[string]string
	Status       string
	StatusReason string
	RegisteredAt time.Time
	EndedAt      time.Time
	TokenHash    [sha256.Size]byte
	TokenExpiry  time.Time
}

type RunStore struct {
	mu             sync.RWMutex
	runs           map[string]AgentRun
	activeByCgroup map[uint64]string
	latestByCgroup map[uint64]string
	liveByIdentity map[ScopeIdentity]string
	terminating    map[string]struct{}
	tombstones     map[ScopeIdentity]runTombstone
	tombstoneSeq   uint64
}

func NewRunStore() *RunStore {
	return &RunStore{
		runs:           make(map[string]AgentRun),
		activeByCgroup: make(map[uint64]string),
		latestByCgroup: make(map[uint64]string),
		liveByIdentity: make(map[ScopeIdentity]string),
		terminating:    make(map[string]struct{}),
		tombstones:     make(map[ScopeIdentity]runTombstone),
	}
}

func (store *RunStore) Add(run AgentRun) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.runs == nil {
		store.runs = make(map[string]AgentRun)
		store.activeByCgroup = make(map[uint64]string)
		store.latestByCgroup = make(map[uint64]string)
		store.liveByIdentity = make(map[ScopeIdentity]string)
		store.terminating = make(map[string]struct{})
		store.tombstones = make(map[ScopeIdentity]runTombstone)
	}
	if _, exists := store.runs[run.RunID]; exists {
		return errors.New("run ID already exists")
	}
	if run.Status == "active" {
		identity := run.scopeIdentity()
		if err := identity.Validate(); err != nil {
			return err
		}
		store.pruneTombstonesLocked(run.RegisteredAt)
		if _, exists := store.liveByIdentity[identity]; exists {
			return ErrScopeIdentityCollision
		}
		if _, exists := store.tombstones[identity]; exists {
			return ErrScopeIdentityCollision
		}
		if _, exists := store.activeByCgroup[run.CgroupID]; exists {
			return errors.New("active run already exists for cgroup")
		}
		store.activeByCgroup[run.CgroupID] = run.RunID
		store.liveByIdentity[identity] = run.RunID
	}
	store.latestByCgroup[run.CgroupID] = run.RunID
	run.Labels = cloneLabels(run.Labels)
	store.runs[run.RunID] = run
	return nil
}

func (store *RunStore) Get(runID string) (AgentRun, bool) {
	store.mu.RLock()
	defer store.mu.RUnlock()
	run, exists := store.runs[runID]
	run.Labels = cloneLabels(run.Labels)
	return run, exists
}

func (store *RunStore) Len() int {
	store.mu.RLock()
	defer store.mu.RUnlock()
	return len(store.runs)
}

func (store *RunStore) FailScope(cgroupID uint64, reason string) (AgentRun, bool, bool) {
	store.mu.Lock()
	defer store.mu.Unlock()
	runID, exists := store.activeByCgroup[cgroupID]
	if !exists {
		runID, exists = store.latestByCgroup[cgroupID]
		if !exists {
			return AgentRun{}, false, false
		}
		run := store.runs[runID]
		run.Labels = cloneLabels(run.Labels)
		return run, false, true
	}
	run := store.runs[runID]
	run.Status = "failed"
	run.StatusReason = reason
	store.runs[runID] = run
	delete(store.activeByCgroup, cgroupID)
	run.Labels = cloneLabels(run.Labels)
	return run, true, true
}

type RegistrationHandler struct {
	registrar           Registrar
	store               *RunStore
	random              io.Reader
	now                 func() time.Time
	tokenTTL            time.Duration
	tombstoneTTL        time.Duration
	tombstoneMaxEntries int
	instanceID          uint64
	signingKey          [sha256.Size]byte
}

type RegistrationOptions struct {
	Random              io.Reader
	Now                 func() time.Time
	TokenTTL            time.Duration
	TombstoneTTL        time.Duration
	TombstoneMaxEntries int
}

func NewRegistrationHandler(registrar Registrar, store *RunStore, options RegistrationOptions) (*RegistrationHandler, error) {
	if registrar == nil {
		return nil, errors.New("scope registrar is required")
	}
	if store == nil {
		store = NewRunStore()
	}
	if options.Random == nil {
		options.Random = rand.Reader
	}
	if options.Now == nil {
		options.Now = time.Now
	}
	if options.TokenTTL == 0 {
		options.TokenTTL = defaultTokenTTL
	}
	if options.TokenTTL < time.Second || options.TokenTTL > time.Hour {
		return nil, errors.New("token TTL must be between one second and one hour")
	}
	if options.TombstoneTTL == 0 {
		options.TombstoneTTL = defaultTombstoneTTL
	}
	if options.TombstoneTTL < time.Second || options.TombstoneTTL > defaultTombstoneTTL {
		return nil, fmt.Errorf("tombstone TTL must be between one second and %s", defaultTombstoneTTL)
	}
	if options.TombstoneMaxEntries == 0 {
		options.TombstoneMaxEntries = defaultTombstoneMaxEntries
	}
	if options.TombstoneMaxEntries < 1 || options.TombstoneMaxEntries > defaultTombstoneMaxEntries {
		return nil, fmt.Errorf("tombstone maximum must be between one and %d entries", defaultTombstoneMaxEntries)
	}

	instanceID, err := randomNonZeroUint64(options.Random)
	if err != nil {
		return nil, fmt.Errorf("generate Core instance ID: %w", err)
	}
	handler := &RegistrationHandler{
		registrar:           registrar,
		store:               store,
		random:              options.Random,
		now:                 options.Now,
		tokenTTL:            options.TokenTTL,
		tombstoneTTL:        options.TombstoneTTL,
		tombstoneMaxEntries: options.TombstoneMaxEntries,
		instanceID:          instanceID,
	}
	if _, err := io.ReadFull(options.Random, handler.signingKey[:]); err != nil {
		return nil, fmt.Errorf("generate ingest signing key: %w", err)
	}
	return handler, nil
}

func (handler *RegistrationHandler) Routes() http.Handler {
	mux := http.NewServeMux()
	mux.Handle(RegisterPath, handler)
	mux.HandleFunc("POST /api/v1/agents/{run_id}/finish", handler.serveFinish)
	return mux
}

func (handler *RegistrationHandler) ServeHTTP(response http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodPost {
		response.Header().Set("Allow", http.MethodPost)
		http.Error(response, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var input RegisterRequest
	decoder := json.NewDecoder(http.MaxBytesReader(response, request.Body, maxRequestBytes))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&input); err != nil {
		http.Error(response, "invalid registration request", http.StatusBadRequest)
		return
	}
	if err := ensureJSONEOF(decoder); err != nil {
		http.Error(response, "invalid registration request", http.StatusBadRequest)
		return
	}
	input.AgentName = strings.TrimSpace(input.AgentName)
	if input.AgentName == "" || len(input.AgentName) > 128 {
		http.Error(response, "agent_name is required and must not exceed 128 bytes", http.StatusBadRequest)
		return
	}
	if input.CgroupPath == "" || input.PID != 0 || input.RootPID < 0 {
		http.Error(response, "a trusted cgroup_path is required; pid scope selection is unsupported", http.StatusBadRequest)
		return
	}
	if input.ScopeMode == "" {
		input.ScopeMode = "leaf_exact"
	}
	if input.ScopeMode != "leaf_exact" {
		http.Error(response, "only leaf_exact scope_mode is supported", http.StatusBadRequest)
		return
	}

	runID, err := randomHex(handler.random, 16)
	if err != nil {
		http.Error(response, "could not allocate run identity", http.StatusInternalServerError)
		return
	}
	cookie, err := randomNonZeroUint64(handler.random)
	if err != nil {
		http.Error(response, "could not allocate scope identity", http.StatusInternalServerError)
		return
	}
	now := handler.now().UTC()
	expiry := now.Add(handler.tokenTTL)
	token, err := handler.signToken(runID, expiry)
	if err != nil {
		http.Error(response, "could not issue ingest token", http.StatusInternalServerError)
		return
	}

	registration, err := handler.registrar.Register(request.Context(), scope.Target{
		Path:    input.CgroupPath,
		RootPID: input.RootPID,
	}, scope.Value{
		InstanceID:  handler.instanceID,
		ScopeCookie: cookie,
		ProfileID:   input.ProfileID,
	})
	if err != nil {
		status := http.StatusInternalServerError
		if errors.Is(err, scope.ErrInvalidTarget) ||
			errors.Is(err, scope.ErrNotLeaf) ||
			errors.Is(err, scope.ErrProtectedScope) {
			status = http.StatusBadRequest
		} else if errors.Is(err, scope.ErrAlreadyActive) || errors.Is(err, scope.ErrOverlap) {
			status = http.StatusConflict
		}
		http.Error(response, http.StatusText(status), status)
		return
	}

	run := AgentRun{
		RunID:        runID,
		AgentName:    input.AgentName,
		ContainerID:  input.ContainerID,
		CgroupID:     registration.CgroupID,
		InstanceID:   handler.instanceID,
		ScopeCookie:  cookie,
		CgroupPath:   registration.Path,
		ScopeMode:    input.ScopeMode,
		RootPID:      input.RootPID,
		ProfileID:    input.ProfileID,
		Labels:       input.Labels,
		Status:       "active",
		RegisteredAt: now,
		TokenHash:    sha256.Sum256([]byte(token)),
		TokenExpiry:  expiry,
	}
	if err := handler.store.Add(run); err != nil {
		_ = handler.registrar.Unregister(registration.CgroupID)
		http.Error(response, "could not persist run", http.StatusInternalServerError)
		return
	}

	output := RegisterResponse{
		RunID:       runID,
		CgroupID:    strconv.FormatUint(registration.CgroupID, 10),
		InstanceID:  strconv.FormatUint(handler.instanceID, 10),
		ScopeCookie: strconv.FormatUint(cookie, 10),
		CgroupPath:  registration.Path,
		ScopeMode:   input.ScopeMode,
		IngestToken: token,
		TokenExpiry: expiry.Format(time.RFC3339Nano),
	}
	response.Header().Set("Content-Type", "application/json")
	response.Header().Set("Cache-Control", "no-store")
	response.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(response).Encode(output)
}

func (handler *RegistrationHandler) VerifyIngestToken(token string) (AgentRun, error) {
	if len(token) == 0 || len(token) > maxTokenBytes {
		return AgentRun{}, errors.New("invalid ingest token")
	}
	encodedPayload, encodedSignature, ok := strings.Cut(token, ".")
	if !ok {
		return AgentRun{}, errors.New("invalid ingest token")
	}
	payload, err := base64.RawURLEncoding.DecodeString(encodedPayload)
	if err != nil {
		return AgentRun{}, errors.New("invalid ingest token")
	}
	signature, err := base64.RawURLEncoding.DecodeString(encodedSignature)
	if err != nil {
		return AgentRun{}, errors.New("invalid ingest token")
	}
	mac := hmac.New(sha256.New, handler.signingKey[:])
	_, _ = mac.Write(payload)
	if !hmac.Equal(signature, mac.Sum(nil)) {
		return AgentRun{}, errors.New("invalid ingest token")
	}
	fields := strings.Split(string(payload), "\n")
	if len(fields) != 3 {
		return AgentRun{}, errors.New("invalid ingest token")
	}
	expiryUnixNano, err := strconv.ParseInt(fields[1], 10, 64)
	if err != nil || !handler.now().Before(time.Unix(0, expiryUnixNano)) {
		return AgentRun{}, errors.New("expired ingest token")
	}
	run, exists := handler.store.Get(fields[0])
	if !exists || !hmac.Equal(run.TokenHash[:], sha256Sum(token)) {
		return AgentRun{}, errors.New("invalid ingest token")
	}
	if run.Status != "active" || !handler.now().Before(run.TokenExpiry) {
		return AgentRun{}, errors.New("inactive or expired ingest token")
	}
	return run, nil
}

func (handler *RegistrationHandler) signToken(runID string, expiry time.Time) (string, error) {
	nonce, err := randomHex(handler.random, 16)
	if err != nil {
		return "", err
	}
	payload := []byte(runID + "\n" + strconv.FormatInt(expiry.UnixNano(), 10) + "\n" + nonce)
	mac := hmac.New(sha256.New, handler.signingKey[:])
	_, _ = mac.Write(payload)
	return base64.RawURLEncoding.EncodeToString(payload) + "." +
		base64.RawURLEncoding.EncodeToString(mac.Sum(nil)), nil
}

func randomNonZeroUint64(random io.Reader) (uint64, error) {
	var encoded [8]byte
	for range 8 {
		if _, err := io.ReadFull(random, encoded[:]); err != nil {
			return 0, err
		}
		value, err := strconv.ParseUint(hex.EncodeToString(encoded[:]), 16, 64)
		if err != nil {
			return 0, err
		}
		if value != 0 {
			return value, nil
		}
	}
	return 0, errors.New("random source returned zero repeatedly")
}

func randomHex(random io.Reader, bytes int) (string, error) {
	value := make([]byte, bytes)
	if _, err := io.ReadFull(random, value); err != nil {
		return "", err
	}
	return hex.EncodeToString(value), nil
}

func ensureJSONEOF(decoder *json.Decoder) error {
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("multiple JSON values")
		}
		return err
	}
	return nil
}

func sha256Sum(value string) []byte {
	sum := sha256.Sum256([]byte(value))
	return sum[:]
}

func cloneLabels(labels map[string]string) map[string]string {
	if labels == nil {
		return nil
	}
	cloned := make(map[string]string, len(labels))
	for key, value := range labels {
		cloned[key] = value
	}
	return cloned
}
