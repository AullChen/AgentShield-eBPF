package bpfmgr

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestEmbeddedSources(t *testing.T) {
	sources := EmbeddedSources()
	if len(sources) != 3 {
		t.Fatalf("len(EmbeddedSources()) = %d, want 3", len(sources))
	}

	required := map[string]bool{
		"../../bpf/agentshield.bpf.c": false,
		"../../bpf/events.h":          false,
		"../../bpf/maps.h":            false,
	}

	for _, source := range sources {
		if source.SHA256 == "" {
			t.Fatalf("source %s has empty SHA256", source.Path)
		}
		if source.Contents == "" {
			t.Fatalf("source %s has empty contents", source.Path)
		}
		if _, ok := required[source.Path]; ok {
			required[source.Path] = true
		}
	}

	for path, found := range required {
		if !found {
			t.Fatalf("generated binding missing %s", path)
		}
	}
}

func TestEmbeddedBPFRejectsUnregisteredScopesBeforeRingBufferReserve(t *testing.T) {
	var program string
	for _, source := range EmbeddedSources() {
		if strings.HasSuffix(source.Path, "agentshield.bpf.c") {
			program = source.Contents
			break
		}
	}
	if program == "" {
		t.Fatal("embedded BPF program source not found")
	}
	for _, function := range []string{
		"int agentshield_trace_execve",
		"int agentshield_trace_openat",
		"agentshield_audit_connect",
	} {
		start := strings.Index(program, function)
		if start < 0 {
			t.Fatalf("BPF function %q not found", function)
		}
		body := program[start:]
		scopeLookup := strings.Index(body, "agentshield_current_scope(")
		reserve := strings.Index(body, "agentshield_reserve_event(")
		if scopeLookup < 0 || reserve < 0 || scopeLookup > reserve {
			t.Fatalf("%s does not check scope before ring-buffer reserve", function)
		}
	}
}

func TestEmbeddedConnectHookReturnsKernelBlockResult(t *testing.T) {
	var program string
	for _, source := range EmbeddedSources() {
		if strings.HasSuffix(source.Path, "agentshield.bpf.c") {
			program = source.Contents
			break
		}
	}
	for _, fragment := range []string{
		"agentshield_network_profile_map",
		"agentshield_network_allow_map",
		"AGENTSHIELD_RESULT_BLOCKED",
		"return blocked ? 0 : 1",
	} {
		if !strings.Contains(program, fragment) {
			t.Fatalf("embedded connect enforcement is missing %q", fragment)
		}
	}
}

func TestEmbeddedSourcesReturnsIndependentSlice(t *testing.T) {
	sources := EmbeddedSources()
	if len(sources) == 0 {
		t.Fatal("EmbeddedSources returned no sources")
	}
	originalPath := sources[0].Path

	sources[0].Path = "modified"
	if got := EmbeddedSources()[0].Path; got != originalPath {
		t.Fatalf("EmbeddedSources()[0].Path = %q after caller mutation, want %q", got, originalPath)
	}
}

func TestEmbeddedSourcesMatchWorkingTree(t *testing.T) {
	_, testFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller could not locate sources_test.go")
	}
	packageDir := filepath.Dir(testFile)

	for _, source := range EmbeddedSources() {
		path := filepath.Join(packageDir, filepath.FromSlash(source.Path))
		contents, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read embedded source %s: %v", source.Path, err)
		}
		if got := string(contents); got != source.Contents {
			t.Fatalf("generated contents for %s are stale; run make generate", source.Path)
		}
		hash := sha256.Sum256(contents)
		if got := hex.EncodeToString(hash[:]); got != source.SHA256 {
			t.Fatalf("generated SHA256 for %s = %s, want %s; run make generate", source.Path, source.SHA256, got)
		}
	}
}
