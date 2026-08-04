package policy

import (
	"errors"
	"fmt"
	"path"
	"slices"
	"strings"
)

type FileIdentity struct {
	Device  uint64
	Inode   uint64
	MountID uint64
}

type FileObservation struct {
	UserPath              string
	UserPathTruncated     bool
	ResolvedPath          string
	ResolvedPathTruncated bool
	Identity              *FileIdentity
	Access                FileAccess
}

type compiledFileRule struct {
	policy Policy
	id     uint32
	kind   string
	value  string
	access []FileAccess
}

type fileCandidate struct {
	value      string
	source     EvidenceSource
	confidence MatchConfidence
	truncated  bool
	reasons    []string
}

func MatchFile(bundle Bundle, observation FileObservation) (MatchResult, error) {
	if err := bundle.Validate(); err != nil {
		return MatchResult{}, fmt.Errorf("validate policy bundle: %w", err)
	}
	if err := validateFileObservation(observation); err != nil {
		return MatchResult{}, err
	}
	rules, err := compileFileRules(bundle)
	if err != nil {
		return MatchResult{}, err
	}
	result := MatchResult{}
	candidates := fileCandidates(observation, &result)
	seen := make(map[uint32]struct{})
	for _, rule := range rules {
		if !slices.Contains(rule.access, observation.Access) {
			continue
		}
		for _, candidate := range candidates {
			if !fileRuleMatches(rule, candidate) {
				continue
			}
			if _, exists := seen[rule.id]; exists {
				break
			}
			reasons := slices.Clone(candidate.reasons)
			if observation.ResolvedPath != "" && observation.UserPath != "" &&
				observation.ResolvedPath != observation.UserPath {
				reasons = append(reasons, "symlink_or_namespace_path_resolved")
			}
			result.Hits = append(result.Hits, PolicyHit{
				PolicyID:        rule.policy.ID,
				RuleID:          rule.id,
				RuleKind:        rule.kind,
				RequestedAction: rule.policy.RequestedAction,
				EffectiveAction: rule.policy.RequestedAction,
				EvidenceSource:  candidate.source,
				Confidence:      candidate.confidence,
				PostEventOnly:   true,
				Reasons:         reasons,
			})
			seen[rule.id] = struct{}{}
			break
		}
	}
	return result, nil
}

func validateFileObservation(observation FileObservation) error {
	if observation.UserPath == "" && observation.ResolvedPath == "" {
		return errors.New("file observation requires a user or resolved path")
	}
	if observation.ResolvedPath != "" && observation.Identity == nil {
		return errors.New("resolved file path requires file identity evidence")
	}
	if observation.Identity != nil && observation.Identity.Inode == 0 {
		return errors.New("file identity requires a non-zero inode")
	}
	if observation.Access != FileRead && observation.Access != FileWrite && observation.Access != FileExecute {
		return fmt.Errorf("file observation access %q is not supported", observation.Access)
	}
	return nil
}

func compileFileRules(bundle Bundle) ([]compiledFileRule, error) {
	registry := make(ruleIDRegistry)
	var rules []compiledFileRule
	for _, policy := range bundle.Policies {
		condition := policy.Conditions.File
		if !policy.Enabled || condition == nil {
			continue
		}
		if policy.RequestedAction != ActionAudit && policy.RequestedAction != ActionAlert {
			return nil, fmt.Errorf("file policy %q requests %q; file string matching supports only audit or alert", policy.ID, policy.RequestedAction)
		}
		groups := []struct {
			kind   string
			values []string
		}{
			{"file_exact", condition.ExactPaths},
			{"file_prefix", condition.Prefixes},
			{"file_suffix", condition.Suffixes},
			{"file_basename", condition.Basenames},
		}
		for _, group := range groups {
			for index, value := range group.values {
				ruleID, err := registry.add(policy.ID, group.kind, index)
				if err != nil {
					return nil, err
				}
				rules = append(rules, compiledFileRule{
					policy: policy,
					id:     ruleID,
					kind:   group.kind,
					value:  value,
					access: condition.Access,
				})
			}
		}
	}
	return rules, nil
}

func fileCandidates(observation FileObservation, result *MatchResult) []fileCandidate {
	var candidates []fileCandidate
	if observation.ResolvedPath != "" {
		confidence := ConfidenceExact
		var reasons []string
		if observation.ResolvedPathTruncated {
			confidence = ConfidenceIncomplete
			reasons = append(reasons, "resolved_path_truncated")
			result.Gaps = append(result.Gaps, EvaluationGap{
				Code: "resolved_path_truncated", Message: "resolved file path is incomplete",
			})
		}
		candidates = append(candidates, fileCandidate{
			value: observation.ResolvedPath, source: EvidenceFileIdentity,
			confidence: confidence, truncated: observation.ResolvedPathTruncated,
			reasons: reasons,
		})
	}
	if observation.UserPath != "" {
		reasons := []string{"user_path_is_not_file_identity"}
		confidence := ConfidenceHeuristic
		if !path.IsAbs(observation.UserPath) {
			reasons = append(reasons, "relative_user_path")
			result.Gaps = append(result.Gaps, EvaluationGap{
				Code: "relative_user_path", Message: "relative path was not resolved against a trusted directory",
			})
		}
		if observation.UserPathTruncated {
			confidence = ConfidenceIncomplete
			reasons = append(reasons, "user_path_truncated")
			result.Gaps = append(result.Gaps, EvaluationGap{
				Code: "user_path_truncated", Message: "user pathname capture is incomplete",
			})
		}
		candidates = append(candidates, fileCandidate{
			value: observation.UserPath, source: EvidenceUserPath,
			confidence: confidence, truncated: observation.UserPathTruncated,
			reasons: reasons,
		})
	}
	return candidates
}

func fileRuleMatches(rule compiledFileRule, candidate fileCandidate) bool {
	switch rule.kind {
	case "file_exact":
		if candidate.truncated {
			return false
		}
		if hasGlob(rule.value) {
			matched, _ := path.Match(rule.value, candidate.value)
			return matched
		}
		return candidate.value == rule.value
	case "file_prefix":
		return strings.HasPrefix(candidate.value, rule.value)
	case "file_suffix":
		return !candidate.truncated && strings.HasSuffix(candidate.value, rule.value)
	case "file_basename":
		return !candidate.truncated && path.Base(candidate.value) == rule.value
	default:
		return false
	}
}
