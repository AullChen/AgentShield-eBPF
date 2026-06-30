package bpfmgr

import "testing"

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
