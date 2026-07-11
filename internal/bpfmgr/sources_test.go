package bpfmgr

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"runtime"
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
