package policy

import (
	"strings"
	"testing"
)

func TestMatchFileReportsStableUserPathHit(t *testing.T) {
	bundle := Bundle{SchemaVersion: SchemaVersion, Policies: []Policy{validPolicy()}}
	observation := FileObservation{
		UserPath: "/demo-secrets/example-token",
		Access:   FileRead,
	}
	first, err := MatchFile(bundle, observation)
	if err != nil {
		t.Fatalf("MatchFile: %v", err)
	}
	second, err := MatchFile(bundle, observation)
	if err != nil {
		t.Fatalf("second MatchFile: %v", err)
	}
	if len(first.Hits) != 1 {
		t.Fatalf("hits = %+v", first.Hits)
	}
	hit := first.Hits[0]
	if hit.RuleID == 0 || hit.RuleID != second.Hits[0].RuleID {
		t.Fatalf("rule IDs = %d and %d", hit.RuleID, second.Hits[0].RuleID)
	}
	if hit.EvidenceSource != EvidenceUserPath || hit.Confidence != ConfidenceHeuristic || !hit.PostEventOnly {
		t.Fatalf("hit semantics = %+v", hit)
	}
	if hit.EffectiveAction != ActionAlert {
		t.Fatalf("effective action = %q", hit.EffectiveAction)
	}
}

func TestMatchFileMatchesBasename(t *testing.T) {
	policy := validPolicy()
	policy.Conditions.File = &FileCondition{Basenames: []string{".env"}, Access: []FileAccess{FileRead}}
	result, err := MatchFile(
		Bundle{SchemaVersion: SchemaVersion, Policies: []Policy{policy}},
		FileObservation{UserPath: "/workspace/project/.env", Access: FileRead},
	)
	if err != nil {
		t.Fatalf("MatchFile: %v", err)
	}
	if len(result.Hits) != 1 || result.Hits[0].RuleKind != "file_basename" {
		t.Fatalf("hits = %+v", result.Hits)
	}
}

func TestMatchFilePrefersResolvedIdentityForSymlink(t *testing.T) {
	bundle := Bundle{SchemaVersion: SchemaVersion, Policies: []Policy{validPolicy()}}
	result, err := MatchFile(bundle, FileObservation{
		UserPath:     "/workspace/token-link",
		ResolvedPath: "/demo-secrets/example-token",
		Identity:     &FileIdentity{Device: 8, Inode: 42, MountID: 7},
		Access:       FileRead,
	})
	if err != nil {
		t.Fatalf("MatchFile: %v", err)
	}
	if len(result.Hits) != 1 {
		t.Fatalf("hits = %+v", result.Hits)
	}
	hit := result.Hits[0]
	if hit.EvidenceSource != EvidenceFileIdentity || hit.Confidence != ConfidenceExact {
		t.Fatalf("hit = %+v", hit)
	}
	if !containsString(hit.Reasons, "symlink_or_namespace_path_resolved") {
		t.Fatalf("reasons = %v", hit.Reasons)
	}
}

func TestMatchFileReportsRelativePathGap(t *testing.T) {
	policy := validPolicy()
	policy.Conditions.File = &FileCondition{ExactPaths: []string{"secrets/token"}, Access: []FileAccess{FileRead}}
	result, err := MatchFile(
		Bundle{SchemaVersion: SchemaVersion, Policies: []Policy{policy}},
		FileObservation{UserPath: "secrets/token", Access: FileRead},
	)
	if err != nil {
		t.Fatalf("MatchFile: %v", err)
	}
	if len(result.Hits) != 1 || result.Hits[0].Confidence != ConfidenceHeuristic {
		t.Fatalf("hits = %+v", result.Hits)
	}
	if len(result.Gaps) != 1 || result.Gaps[0].Code != "relative_user_path" {
		t.Fatalf("gaps = %+v", result.Gaps)
	}
}

func TestMatchFileTruncatedPathOnlyMatchesPrefix(t *testing.T) {
	policy := validPolicy()
	policy.Conditions.File = &FileCondition{
		ExactPaths: []string{"/workspace/project/.env"},
		Prefixes:   []string{"/workspace/"},
		Suffixes:   []string{".env"},
		Access:     []FileAccess{FileRead},
	}
	result, err := MatchFile(
		Bundle{SchemaVersion: SchemaVersion, Policies: []Policy{policy}},
		FileObservation{UserPath: "/workspace/proj", UserPathTruncated: true, Access: FileRead},
	)
	if err != nil {
		t.Fatalf("MatchFile: %v", err)
	}
	if len(result.Hits) != 1 || result.Hits[0].RuleKind != "file_prefix" ||
		result.Hits[0].Confidence != ConfidenceIncomplete {
		t.Fatalf("hits = %+v", result.Hits)
	}
	if len(result.Gaps) != 1 || result.Gaps[0].Code != "user_path_truncated" {
		t.Fatalf("gaps = %+v", result.Gaps)
	}
}

func TestMatchFileDoesNotIgnoreAccessMode(t *testing.T) {
	result, err := MatchFile(
		Bundle{SchemaVersion: SchemaVersion, Policies: []Policy{validPolicy()}},
		FileObservation{UserPath: "/demo-secrets/example-token", Access: FileWrite},
	)
	if err != nil {
		t.Fatalf("MatchFile: %v", err)
	}
	if len(result.Hits) != 0 {
		t.Fatalf("unexpected hits = %+v", result.Hits)
	}
}

func TestMatchFileRejectsBlockAndUnprovenResolvedPath(t *testing.T) {
	policy := validPolicy()
	policy.Decision = DecisionDeny
	policy.RequestedAction = ActionBlock
	_, err := MatchFile(
		Bundle{SchemaVersion: SchemaVersion, Policies: []Policy{policy}},
		FileObservation{UserPath: "/demo-secrets/example-token", Access: FileRead},
	)
	if err == nil || !strings.Contains(err.Error(), "supports only audit or alert") {
		t.Fatalf("block error = %v", err)
	}

	policy = validPolicy()
	_, err = MatchFile(
		Bundle{SchemaVersion: SchemaVersion, Policies: []Policy{policy}},
		FileObservation{ResolvedPath: "/demo-secrets/example-token", Access: FileRead},
	)
	if err == nil || !strings.Contains(err.Error(), "requires file identity") {
		t.Fatalf("identity error = %v", err)
	}
}

func containsString(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}
