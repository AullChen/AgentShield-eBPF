package policy

import (
	"encoding/binary"
	"fmt"
	"hash/fnv"
)

type EvidenceSource string

const (
	EvidenceUserPath     EvidenceSource = "user_path"
	EvidenceFileIdentity EvidenceSource = "file_identity"
	EvidenceExecCapture  EvidenceSource = "exec_capture"
	EvidenceNetworkTuple EvidenceSource = "network_tuple"
)

type MatchConfidence string

const (
	ConfidenceExact      MatchConfidence = "exact"
	ConfidenceHeuristic  MatchConfidence = "heuristic"
	ConfidenceIncomplete MatchConfidence = "incomplete"
)

type PolicyHit struct {
	PolicyID        string          `json:"policy_id"`
	RuleID          uint32          `json:"rule_id"`
	RuleKind        string          `json:"rule_kind"`
	RequestedAction Action          `json:"requested_action"`
	EffectiveAction Action          `json:"effective_action"`
	EvidenceSource  EvidenceSource  `json:"evidence_source"`
	Confidence      MatchConfidence `json:"confidence"`
	PostEventOnly   bool            `json:"post_event_only"`
	ContainmentHint bool            `json:"containment_hint,omitempty"`
	Reasons         []string        `json:"reasons,omitempty"`
}

type EvaluationGap struct {
	PolicyID string `json:"policy_id,omitempty"`
	Code     string `json:"code"`
	Message  string `json:"message"`
}

type MatchResult struct {
	Hits []PolicyHit     `json:"hits"`
	Gaps []EvaluationGap `json:"gaps,omitempty"`
}

type ruleIDRegistry map[uint32]string

func (registry ruleIDRegistry) add(policyID, kind string, index int) (uint32, error) {
	hash := fnv.New32a()
	hash.Write([]byte(policyID))
	hash.Write([]byte{0})
	hash.Write([]byte(kind))
	var encodedIndex [4]byte
	binary.LittleEndian.PutUint32(encodedIndex[:], uint32(index))
	hash.Write(encodedIndex[:])
	ruleID := hash.Sum32()
	if ruleID == 0 {
		ruleID = 1
	}
	identity := fmt.Sprintf("%s/%s/%d", policyID, kind, index)
	if existing, exists := registry[ruleID]; exists && existing != identity {
		return 0, fmt.Errorf("rule ID collision between %q and %q", existing, identity)
	}
	registry[ruleID] = identity
	return ruleID, nil
}
