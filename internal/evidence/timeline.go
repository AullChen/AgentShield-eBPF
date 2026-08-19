package evidence

import (
	"errors"
	"sort"
	"strconv"

	"github.com/agentshield/agentshield-ebpf/internal/correlator"
)

const SchemaVersion = "1"

type Source string

const (
	AgentClaim        Source = "agent_claim"
	KernelFact        Source = "kernel_fact"
	PolicyDecision    Source = "policy_decision"
	ContainmentResult Source = "containment_result"
)

type Attribution struct {
	Status    string `json:"status"`
	RunID     string `json:"run_id,omitempty"`
	RunStatus string `json:"run_status,omitempty"`
	Basis     string `json:"basis"`
}

type OperationResult struct {
	AttemptObserved bool   `json:"attempt_observed"`
	ActionResult    string `json:"action_result"`
	Mechanism       string `json:"mechanism"`
}

type Decision struct {
	PolicyID        string `json:"policy_id"`
	RuleID          string `json:"rule_id"`
	RequestedAction string `json:"requested_action"`
	FinalDecision   string `json:"final_decision"`
	Enforced        bool   `json:"enforced"`
	Mechanism       string `json:"mechanism"`
}

type Containment struct {
	Requested            bool   `json:"requested"`
	Result               string `json:"result"`
	Method               string `json:"method"`
	TargetIdentity       string `json:"target_identity"`
	OriginalActionResult string `json:"original_action_result"`
}

type Item struct {
	Sequence          string             `json:"sequence"`
	ID                string             `json:"id"`
	Type              string             `json:"type"`
	Source            Source             `json:"source"`
	ServerMonotonicNS string             `json:"server_monotonic_ns"`
	ServerUnixNS      string             `json:"server_unix_ns"`
	Summary           string             `json:"summary"`
	Attribution       *Attribution       `json:"attribution,omitempty"`
	Correlation       *correlator.Result `json:"correlation,omitempty"`
	Operation         *OperationResult   `json:"operation,omitempty"`
	Decision          *Decision          `json:"decision,omitempty"`
	Containment       *Containment       `json:"containment,omitempty"`
	monotonicNS       uint64
}

type Timeline struct {
	SchemaVersion string `json:"schema_version"`
	RunID         string `json:"run_id"`
	Items         []Item `json:"items"`
}

type Event struct {
	ID                string
	Type              string
	Source            Source
	ServerMonotonicNS uint64
	ServerUnixNS      uint64
	Summary           string
	Attribution       *Attribution
	Correlation       *correlator.Result
	Operation         *OperationResult
	Decision          *Decision
	Containment       *Containment
}

func Build(runID string, events []Event) (Timeline, error) {
	if runID == "" || len(events) > 10_000 {
		return Timeline{}, errors.New("timeline input is invalid")
	}
	items := make([]Item, 0, len(events))
	seen := make(map[string]struct{}, len(events))
	for _, event := range events {
		if event.ID == "" || event.Type == "" || event.ServerMonotonicNS == 0 || event.ServerUnixNS == 0 || len(event.Summary) > 4096 {
			return Timeline{}, errors.New("timeline event is invalid")
		}
		if _, exists := seen[event.ID]; exists {
			return Timeline{}, errors.New("timeline event ID is duplicated")
		}
		seen[event.ID] = struct{}{}
		if err := validateSource(event); err != nil {
			return Timeline{}, err
		}
		items = append(items, Item{ID: event.ID, Type: event.Type, Source: event.Source,
			ServerMonotonicNS: strconv.FormatUint(event.ServerMonotonicNS, 10), ServerUnixNS: strconv.FormatUint(event.ServerUnixNS, 10),
			Summary: event.Summary, Attribution: event.Attribution, Correlation: event.Correlation,
			Operation: event.Operation, Decision: event.Decision, Containment: event.Containment, monotonicNS: event.ServerMonotonicNS})
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].monotonicNS != items[j].monotonicNS {
			return items[i].monotonicNS < items[j].monotonicNS
		}
		return items[i].ID < items[j].ID
	})
	for index := range items {
		items[index].Sequence = strconv.Itoa(index + 1)
		items[index].monotonicNS = 0
	}
	return Timeline{SchemaVersion: SchemaVersion, RunID: runID, Items: items}, nil
}

func validateSource(event Event) error {
	switch event.Source {
	case AgentClaim:
		if event.Operation != nil || event.Decision != nil || event.Containment != nil {
			return errors.New("agent claim contains authoritative result")
		}
	case KernelFact:
		if event.Operation == nil || event.Decision != nil || event.Containment != nil {
			return errors.New("kernel fact has invalid evidence fields")
		}
	case PolicyDecision:
		if event.Decision == nil || event.Containment != nil {
			return errors.New("policy decision has invalid evidence fields")
		}
	case ContainmentResult:
		if event.Containment == nil || event.Decision != nil || event.Operation != nil {
			return errors.New("containment result has invalid evidence fields")
		}
	default:
		return errors.New("timeline source is invalid")
	}
	return nil
}
