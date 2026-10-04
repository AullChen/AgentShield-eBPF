// Package inspection performs local-only preflight checks. It has no upstream
// transport and never executes tools. A checked result is not execution proof
// or a transferable authorization capability for an external executor.
package inspection

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"
)

const MaxBody = 256 << 10

var identifier = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)
var runIdentifier = regexp.MustCompile(`^[0-9a-f]{32}$`)
var digestPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)

type Route struct {
	ID   string     `json:"id"`
	Kind string     `json:"kind"`
	MCP  *MCPPolicy `json:"mcp,omitempty"`
}
type Config struct {
	Routes         []Route  `json:"routes"`
	SensitiveFiles []string `json:"sensitive_files"`
	RequestsPerRun int      `json:"requests_per_run"`
	Concurrency    int      `json:"concurrency"`
}
type Decision struct {
	RunID, RouteID, SHA256, Reason string
	Checked                        bool
}
type Options struct {
	Authenticate func(string) (string, error)
	ActiveRun    func(string) bool
	Audit        func(Decision) error
}
type Approval struct {
	RunID     string    `json:"run_id"`
	RouteID   string    `json:"route_id"`
	SHA256    string    `json:"sha256"`
	ExpiresAt time.Time `json:"expires_at"`
}
type Checker struct {
	routes    map[string]Route
	forbidden []string
	options   Options
	ownerRead func(string) ([]byte, error)
	mu        sync.Mutex
	approvals map[string]time.Time
	counts    map[string]int
	limit     int
	slots     chan struct{}
	now       func() time.Time
}

// ownerRead must reject symlinks, untrusted ownership and permissive files.
func Load(path string, ownerRead func(string) ([]byte, error)) (Config, error) {
	data, err := ownerRead(path)
	if err != nil {
		return Config{}, err
	}
	if _, err := decodeObject(data); err != nil {
		return Config{}, errors.New("invalid inspection configuration")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var cfg Config
	if decoder.Decode(&cfg) != nil || decoder.Decode(new(any)) != io.EOF {
		return Config{}, errors.New("invalid inspection configuration")
	}
	return cfg, nil
}

func New(cfg Config, options Options, ownerRead func(string) ([]byte, error)) (*Checker, error) {
	if options.Authenticate == nil || options.ActiveRun == nil || options.Audit == nil || ownerRead == nil ||
		len(cfg.Routes) < 1 || len(cfg.Routes) > 32 || len(cfg.SensitiveFiles) > 32 || cfg.RequestsPerRun < 1 || cfg.RequestsPerRun > 10000 || cfg.Concurrency < 1 || cfg.Concurrency > 16 {
		return nil, errors.New("invalid inspection configuration")
	}
	checker := &Checker{routes: map[string]Route{}, options: options, ownerRead: ownerRead, approvals: map[string]time.Time{}, counts: map[string]int{}, limit: cfg.RequestsPerRun, slots: make(chan struct{}, cfg.Concurrency), now: time.Now}
	for _, route := range cfg.Routes {
		if !identifier.MatchString(route.ID) {
			return nil, errors.New("invalid inspection route")
		}
		if _, exists := checker.routes[route.ID]; exists {
			return nil, errors.New("duplicate inspection route")
		}
		switch route.Kind {
		case "model":
			if route.MCP != nil {
				return nil, errors.New("unexpected MCP configuration")
			}
		case "mcp":
			if route.MCP == nil {
				return nil, errors.New("missing MCP policy")
			}
			if err := checker.validateMCP(route.MCP); err != nil {
				return nil, err
			}
		default:
			return nil, errors.New("unsupported inspection kind")
		}
		checker.routes[route.ID] = route
	}
	for _, path := range cfg.SensitiveFiles {
		data, err := ownerRead(path)
		if err != nil || len(data) < 8 || len(data) > MaxBody {
			return nil, errors.New("invalid sensitive-value file")
		}
		checker.forbidden = append(checker.forbidden, string(data))
	}
	return checker, nil
}

func approvalKey(run, route, digest string) string { return run + "/" + route + "/" + digest }

func (checker *Checker) Approve(approval Approval) error {
	now := checker.now()
	if !runIdentifier.MatchString(approval.RunID) || !digestPattern.MatchString(approval.SHA256) || !checker.options.ActiveRun(approval.RunID) ||
		!approval.ExpiresAt.After(now) || approval.ExpiresAt.After(now.Add(5*time.Minute)) {
		return errors.New("invalid or inactive approval")
	}
	if _, exists := checker.routes[approval.RouteID]; !exists {
		return errors.New("unknown inspection route")
	}
	checker.mu.Lock()
	defer checker.mu.Unlock()
	for key, expiry := range checker.approvals {
		if !expiry.After(now) {
			delete(checker.approvals, key)
		}
	}
	if len(checker.approvals) >= 1024 {
		return errors.New("approval capacity reached")
	}
	if err := checker.options.Audit(Decision{RunID: approval.RunID, RouteID: approval.RouteID, SHA256: approval.SHA256, Reason: "approval_granted"}); err != nil {
		return errors.New("audit unavailable")
	}
	checker.approvals[approvalKey(approval.RunID, approval.RouteID, approval.SHA256)] = approval.ExpiresAt
	return nil
}

// ManagementRoutes MUST be mounted only on the owner-only management socket.
func (checker *Checker) ManagementRoutes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/v1/inspection/approvals", func(w http.ResponseWriter, r *http.Request) {
		data, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 2048))
		if err != nil || r.Header.Get("Origin") != "" || r.URL.RawQuery != "" {
			http.Error(w, "invalid approval", 400)
			return
		}
		if _, err := decodeObject(data); err != nil {
			http.Error(w, "invalid approval", 400)
			return
		}
		decoder := json.NewDecoder(bytes.NewReader(data))
		decoder.DisallowUnknownFields()
		var approval Approval
		if decoder.Decode(&approval) != nil || checker.Approve(approval) != nil {
			http.Error(w, "approval rejected", 400)
			return
		}
		w.WriteHeader(http.StatusCreated)
	})
	return mux
}

func (checker *Checker) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if r.Method != http.MethodPost || r.URL.RawQuery != "" || r.URL.RawPath != "" || r.Header.Get("Origin") != "" || r.Header.Get("Mcp-Session-Id") != "" {
		http.Error(w, "unsupported local check", 400)
		return
	}
	id := strings.TrimPrefix(r.URL.Path, "/gateway/v1/check/")
	route, exists := checker.routes[id]
	if !exists || r.URL.Path != "/gateway/v1/check/"+id {
		http.NotFound(w, r)
		return
	}
	authorization := r.Header.Get("Authorization")
	run, err := checker.options.Authenticate(strings.TrimPrefix(authorization, "Bearer "))
	if err != nil || !strings.HasPrefix(authorization, "Bearer ") || !runIdentifier.MatchString(run) {
		http.Error(w, "unauthorized", 401)
		return
	}
	select {
	case checker.slots <- struct{}{}:
		defer func() { <-checker.slots }()
	default:
		http.Error(w, "inspection busy", 429)
		return
	}
	if allowed, audit := checker.reserveBudget(run); !allowed {
		if audit {
			checker.result(w, run, id, "", "request_budget", false, 429)
		} else {
			// Do not permit rejected-request floods to grow the evidence store.
			http.Error(w, "request budget exhausted", 429)
		}
		return
	}
	media, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || media != "application/json" || r.Header.Get("Content-Encoding") != "" {
		checker.result(w, run, id, "", "unsupported_content", false, 415)
		return
	}
	data, err := io.ReadAll(http.MaxBytesReader(w, r.Body, MaxBody))
	if err != nil {
		checker.result(w, run, id, "", "body_limit", false, 413)
		return
	}
	hash := sha256.Sum256(data)
	digest := hex.EncodeToString(hash[:])
	object, err := decodeObject(data)
	if err != nil {
		checker.result(w, run, id, digest, "invalid_json", false, 400)
		return
	}
	if sensitive(object, checker.forbidden) {
		checker.result(w, run, id, digest, "sensitive_data", false, 403)
		return
	}
	if route.MCP != nil {
		if err := checker.checkMCP(route.MCP, object); err != nil {
			checker.result(w, run, id, digest, err.Error(), false, 403)
			return
		}
	}
	checker.mu.Lock()
	key := approvalKey(run, id, digest)
	expiry, approved := checker.approvals[key]
	delete(checker.approvals, key)
	reason := "checked"
	if !approved || !expiry.After(checker.now()) {
		reason = "approval_required"
	}
	checker.mu.Unlock()
	if !checker.options.ActiveRun(run) {
		checker.result(w, run, id, digest, "inactive_run", false, 401)
		return
	}
	if reason != "checked" {
		checker.result(w, run, id, digest, reason, false, 403)
		return
	}
	checker.result(w, run, id, digest, reason, true, 200)
}

func (checker *Checker) reserveBudget(run string) (allowed, audit bool) {
	checker.mu.Lock()
	defer checker.mu.Unlock()
	for id := range checker.counts {
		if !checker.options.ActiveRun(id) {
			delete(checker.counts, id)
		}
	}
	if len(checker.counts) >= 1024 && checker.counts[run] == 0 {
		return false, false
	}
	if checker.counts[run] >= checker.limit {
		if checker.counts[run] == checker.limit {
			checker.counts[run]++
			return false, true
		}
		return false, false
	}
	checker.counts[run]++
	return true, true
}

func (checker *Checker) result(w http.ResponseWriter, run, route, digest, reason string, checked bool, status int) {
	if err := checker.options.Audit(Decision{RunID: run, RouteID: route, SHA256: digest, Reason: reason, Checked: checked}); err != nil {
		status, reason, checked = 503, "audit_unavailable", false
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{"mode": "local_only", "checked": checked, "reason": reason, "sha256": digest, "forwarded": false, "executed": false})
}
