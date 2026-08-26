package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/agentshield/agentshield-ebpf/internal/policy"
)

type PolicyGeneration struct {
	Revision string `json:"revision"`
	Bank     string `json:"bank"`
}

type PolicySummary struct {
	ID              string `json:"id"`
	Name            string `json:"name"`
	Description     string `json:"description,omitempty"`
	Enabled         bool   `json:"enabled"`
	Scope           string `json:"scope"`
	Decision        string `json:"decision"`
	RequestedAction string `json:"requested_action"`
	Severity        string `json:"severity"`
	Condition       string `json:"condition"`
	Priority        int    `json:"priority"`
}

type PolicySnapshot struct {
	SchemaVersion string           `json:"schema_version"`
	GeneratedAt   string           `json:"generated_at"`
	Configured    bool             `json:"configured"`
	Generation    PolicyGeneration `json:"generation"`
	Policies      []PolicySummary  `json:"policies"`
}

type PolicyProvider interface {
	Policies(context.Context) (PolicySnapshot, error)
}

type PolicyCatalog struct {
	now        func() time.Time
	configured bool
	generation PolicyGeneration
	policies   []PolicySummary
}

type PolicyCatalogOptions struct {
	Now func() time.Time
}

func NewPolicyCatalog(bundle *policy.Bundle, generation policy.Generation, options PolicyCatalogOptions) (*PolicyCatalog, error) {
	if options.Now == nil {
		options.Now = time.Now
	}
	catalog := &PolicyCatalog{now: options.Now, policies: []PolicySummary{}}
	if bundle == nil {
		return catalog, nil
	}
	if generation.Revision == 0 || (generation.Bank != policy.BankA && generation.Bank != policy.BankB) {
		return nil, errors.New("configured policy catalog requires a valid generation")
	}
	catalog.configured = true
	catalog.generation = PolicyGeneration{Revision: strconv.FormatUint(generation.Revision, 10), Bank: policyBankName(generation.Bank)}
	catalog.policies = make([]PolicySummary, 0, len(bundle.Policies))
	for _, configured := range bundle.Policies {
		catalog.policies = append(catalog.policies, PolicySummary{
			ID: configured.ID, Name: configured.Name, Description: configured.Description,
			Enabled: configured.Enabled, Scope: policyScope(configured.Scope), Decision: string(configured.Decision),
			RequestedAction: string(configured.RequestedAction), Severity: string(configured.Severity),
			Condition: policyCondition(configured.Conditions), Priority: configured.Priority,
		})
	}
	sort.SliceStable(catalog.policies, func(left, right int) bool {
		if catalog.policies[left].Priority != catalog.policies[right].Priority {
			return catalog.policies[left].Priority > catalog.policies[right].Priority
		}
		return catalog.policies[left].ID < catalog.policies[right].ID
	})
	return catalog, nil
}

func (catalog *PolicyCatalog) Policies(context.Context) (PolicySnapshot, error) {
	return PolicySnapshot{
		SchemaVersion: "1", GeneratedAt: catalog.now().UTC().Format(time.RFC3339Nano),
		Configured: catalog.configured, Generation: catalog.generation,
		Policies: append([]PolicySummary{}, catalog.policies...),
	}, nil
}

func policyScope(scope policy.Scope) string {
	switch scope.Type {
	case policy.ScopeRun:
		return "run:" + scope.RunID
	case policy.ScopeCgroup:
		return "cgroup:" + scope.CgroupID
	case policy.ScopeLabels:
		keys := make([]string, 0, len(scope.LabelSelector))
		for key := range scope.LabelSelector {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		selectors := make([]string, 0, len(keys))
		for _, key := range keys {
			selectors = append(selectors, key+"="+scope.LabelSelector[key])
		}
		return "labels:" + strings.Join(selectors, ",")
	default:
		return string(scope.Type)
	}
}

func policyCondition(conditions policy.Conditions) string {
	if conditions.File != nil {
		return "file"
	}
	if conditions.Exec != nil {
		return "exec"
	}
	if conditions.Network != nil {
		return "network"
	}
	return "unknown"
}

func policyBankName(bank policy.Bank) string {
	if bank == policy.BankA {
		return "A"
	}
	return "B"
}

type PolicyHandlerOptions struct {
	ReadToken string
}

type PolicyHandler struct {
	provider PolicyProvider
	auth     readAuthorizer
}

func NewPolicyHandler(provider PolicyProvider, options PolicyHandlerOptions) (*PolicyHandler, error) {
	if provider == nil {
		return nil, errors.New("policy provider is required")
	}
	auth, err := newReadAuthorizer(options.ReadToken)
	if err != nil {
		return nil, fmt.Errorf("policy authentication: %w", err)
	}
	return &PolicyHandler{provider: provider, auth: auth}, nil
}

func (handler *PolicyHandler) Routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/v1/policies", handler.ServeHTTP)
	return mux
}

func (handler *PolicyHandler) ServeHTTP(response http.ResponseWriter, request *http.Request) {
	if !handler.auth.authorized(request.Header.Get("Authorization")) {
		response.Header().Set("WWW-Authenticate", "Bearer")
		http.Error(response, "unauthorized", http.StatusUnauthorized)
		return
	}
	snapshot, err := handler.provider.Policies(request.Context())
	if err != nil {
		http.Error(response, "policies unavailable", http.StatusServiceUnavailable)
		return
	}
	response.Header().Set("Cache-Control", "no-store")
	response.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(response).Encode(snapshot)
}
