package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/http"
	"sort"
	"strconv"
	"sync"
	"time"
	"unsafe"

	"github.com/agentshield/agentshield-ebpf/internal/envcheck"
	"github.com/agentshield/agentshield-ebpf/internal/policy"
)

type LoadAttachProbe struct {
	Status string `json:"status"`
	Detail string `json:"detail"`
}

type HookStatus struct {
	Name   string `json:"name"`
	Status string `json:"status"`
	Detail string `json:"detail"`
}

type DropCount struct {
	EventType string `json:"event_type"`
	Count     string `json:"count"`
}

type DiagnosticsSnapshot struct {
	SchemaVersion    string           `json:"schema_version"`
	GeneratedAt      string           `json:"generated_at"`
	OS               string           `json:"os"`
	Arch             string           `json:"arch"`
	ByteOrder        string           `json:"byte_order"`
	Checks           []envcheck.Check `json:"checks"`
	LoadAttach       LoadAttachProbe  `json:"load_attach"`
	Hooks            []HookStatus     `json:"hooks"`
	PolicyGeneration PolicyGeneration `json:"policy_generation"`
	Drops            []DropCount      `json:"drops"`
}

type DiagnosticsProvider interface {
	Diagnostics(context.Context) (DiagnosticsSnapshot, error)
}

type DiagnosticsState struct {
	mu               sync.RWMutex
	now              func() time.Time
	report           envcheck.Report
	byteOrder        string
	loadAttach       LoadAttachProbe
	hooks            []HookStatus
	policyGeneration PolicyGeneration
	drops            map[string]uint64
}

type DiagnosticsStateOptions struct {
	Now func() time.Time
}

func NewDiagnosticsState(report envcheck.Report, generation policy.Generation, options DiagnosticsStateOptions) (*DiagnosticsState, error) {
	if report.OS == "" || report.Arch == "" {
		return nil, errors.New("diagnostics environment report is incomplete")
	}
	if options.Now == nil {
		options.Now = time.Now
	}
	policyGeneration := PolicyGeneration{}
	if generation.Revision != 0 {
		if generation.Bank != policy.BankA && generation.Bank != policy.BankB {
			return nil, errors.New("diagnostics policy generation bank is invalid")
		}
		policyGeneration = PolicyGeneration{Revision: strconv.FormatUint(generation.Revision, 10), Bank: policyBankName(generation.Bank)}
	}
	hooks := []HookStatus{
		{Name: "tracepoint/syscalls/sys_enter_execve", Status: "pending", Detail: "load and attach not yet completed"},
		{Name: "tracepoint/syscalls/sys_enter_openat", Status: "pending", Detail: "load and attach not yet completed"},
		{Name: "cgroup/connect4", Status: "pending", Detail: "load and attach not yet completed"},
		{Name: "cgroup/connect6", Status: "pending", Detail: "load and attach not yet completed"},
	}
	return &DiagnosticsState{
		now: options.Now, report: cloneEnvironmentReport(report), byteOrder: nativeByteOrder(),
		loadAttach: LoadAttachProbe{Status: "unknown", Detail: "actual BPF load and attach has not completed"},
		hooks:      hooks, policyGeneration: policyGeneration, drops: make(map[string]uint64),
	}, nil
}

func (state *DiagnosticsState) MarkHooksReady() {
	state.mu.Lock()
	state.loadAttach = LoadAttachProbe{Status: "available", Detail: "BPF object loaded and all configured hooks attached"}
	for index := range state.hooks {
		state.hooks[index].Status = "attached"
		state.hooks[index].Detail = "confirmed by the running Go loader"
	}
	state.mu.Unlock()
}

func (state *DiagnosticsState) MarkLoadAttachFailed(err error) {
	if err == nil {
		return
	}
	state.mu.Lock()
	defer state.mu.Unlock()
	if state.loadAttach.Status == "available" {
		return
	}
	detail := err.Error()
	if len(detail) > 512 {
		detail = detail[:512]
	}
	state.loadAttach = LoadAttachProbe{Status: "unavailable", Detail: detail}
	for index := range state.hooks {
		state.hooks[index].Status = "not_attached"
		state.hooks[index].Detail = "load or attach did not complete"
	}
}

func (state *DiagnosticsState) ObserveDrop(eventType string, count uint64) error {
	if eventType == "" || len(eventType) > 64 || count == 0 {
		return errors.New("invalid per-type drop count")
	}
	state.mu.Lock()
	defer state.mu.Unlock()
	if state.drops[eventType] > math.MaxUint64-count {
		return errors.New("per-type drop count overflow")
	}
	state.drops[eventType] += count
	return nil
}

func (state *DiagnosticsState) Diagnostics(context.Context) (DiagnosticsSnapshot, error) {
	state.mu.RLock()
	defer state.mu.RUnlock()
	hooks := append([]HookStatus{}, state.hooks...)
	drops := make([]DropCount, 0, len(state.drops))
	for eventType, count := range state.drops {
		drops = append(drops, DropCount{EventType: eventType, Count: strconv.FormatUint(count, 10)})
	}
	sort.Slice(drops, func(left, right int) bool { return drops[left].EventType < drops[right].EventType })
	return DiagnosticsSnapshot{
		SchemaVersion: "1", GeneratedAt: state.now().UTC().Format(time.RFC3339Nano),
		OS: state.report.OS, Arch: state.report.Arch, ByteOrder: state.byteOrder,
		Checks: cloneEnvironmentReport(state.report).Checks, LoadAttach: state.loadAttach,
		Hooks: hooks, PolicyGeneration: state.policyGeneration, Drops: drops,
	}, nil
}

func nativeByteOrder() string {
	value := uint16(0x0102)
	first := *(*byte)(unsafe.Pointer(&value))
	if first == 0x02 {
		return "little-endian"
	}
	return "big-endian"
}

func cloneEnvironmentReport(report envcheck.Report) envcheck.Report {
	cloned := envcheck.Report{OS: report.OS, Arch: report.Arch, Checks: make([]envcheck.Check, len(report.Checks))}
	for index, check := range report.Checks {
		details := make(map[string]string, len(check.Details))
		for key, value := range check.Details {
			details[key] = value
		}
		cloned.Checks[index] = envcheck.Check{Name: check.Name, Status: check.Status, Message: check.Message, Details: details}
	}
	return cloned
}

type DiagnosticsHandlerOptions struct {
	ReadToken string
}

type DiagnosticsHandler struct {
	provider DiagnosticsProvider
	auth     readAuthorizer
}

func NewDiagnosticsHandler(provider DiagnosticsProvider, options DiagnosticsHandlerOptions) (*DiagnosticsHandler, error) {
	if provider == nil {
		return nil, errors.New("diagnostics provider is required")
	}
	auth, err := newReadAuthorizer(options.ReadToken)
	if err != nil {
		return nil, fmt.Errorf("diagnostics authentication: %w", err)
	}
	return &DiagnosticsHandler{provider: provider, auth: auth}, nil
}

func (handler *DiagnosticsHandler) Routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/v1/diagnostics", handler.ServeHTTP)
	return mux
}

func (handler *DiagnosticsHandler) ServeHTTP(response http.ResponseWriter, request *http.Request) {
	if !handler.auth.authorized(request.Header.Get("Authorization")) {
		response.Header().Set("WWW-Authenticate", "Bearer")
		http.Error(response, "unauthorized", http.StatusUnauthorized)
		return
	}
	snapshot, err := handler.provider.Diagnostics(request.Context())
	if err != nil {
		http.Error(response, "diagnostics unavailable", http.StatusServiceUnavailable)
		return
	}
	response.Header().Set("Cache-Control", "no-store")
	response.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(response).Encode(snapshot)
}
