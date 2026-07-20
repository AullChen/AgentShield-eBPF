package main

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cilium/ebpf"
)

func TestMetadataFlagsRejectInvalidValues(t *testing.T) {
	for _, value := range []string{"", "missing-value=", "=missing-key", "missing-separator"} {
		values := metadataFlags{}
		if err := values.Set(value); err == nil {
			t.Fatalf("Set(%q) returned nil error", value)
		}
	}
}

func TestMetadataFlagsAreStableAndLastValueWins(t *testing.T) {
	values := metadataFlags{}
	for _, value := range []string{"z=last", "a=first", "z=replaced"} {
		if err := values.Set(value); err != nil {
			t.Fatalf("Set(%q): %v", value, err)
		}
	}
	if got, want := values.String(), "a=first,z=replaced"; got != want {
		t.Fatalf("String() = %q, want %q", got, want)
	}
}

func TestRunRequiresObject(t *testing.T) {
	err := run(nil, &bytes.Buffer{})
	if err == nil || !strings.Contains(err.Error(), "--object is required") {
		t.Fatalf("run error = %v, want missing object error", err)
	}
}

func TestRunRejectsInvalidELF(t *testing.T) {
	err := run([]string{"--object", "main_test.go"}, &bytes.Buffer{})
	if err == nil || !strings.Contains(err.Error(), "parse BPF ELF/spec") {
		t.Fatalf("run error = %v, want parse error", err)
	}
}

func TestRunDoesNotOverwriteObjectWithManifest(t *testing.T) {
	objectPath := filepath.Join(t.TempDir(), "agentshield.bpf.o")
	const contents = "not an ELF, but it must remain intact"
	if err := os.WriteFile(objectPath, []byte(contents), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	err := run([]string{"--object", objectPath, "--manifest", objectPath}, io.Discard)
	if err == nil || !strings.Contains(err.Error(), "must not overwrite") {
		t.Fatalf("run error = %v, want overwrite rejection", err)
	}
	payload, readErr := os.ReadFile(objectPath)
	if readErr != nil {
		t.Fatalf("ReadFile: %v", readErr)
	}
	if string(payload) != contents {
		t.Fatalf("object contents = %q, want %q", payload, contents)
	}
}

func TestVerifyManifestAcceptsMatchingObjectDescription(t *testing.T) {
	manifest := objectManifest{SchemaVersion: 1, SHA256: "abc", Size: 10, ByteOrder: "LittleEndian"}
	payload, err := json.Marshal(manifest)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	path := filepath.Join(t.TempDir(), "manifest.json")
	if err := os.WriteFile(path, payload, 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if err := verifyManifest(path, manifest); err != nil {
		t.Fatalf("verifyManifest returned error: %v", err)
	}
}

func TestVerifyManifestRejectsDifferentHash(t *testing.T) {
	expected := objectManifest{SchemaVersion: 1, SHA256: "old", Size: 10, ByteOrder: "LittleEndian"}
	payload, err := json.Marshal(expected)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	path := filepath.Join(t.TempDir(), "manifest.json")
	if err := os.WriteFile(path, payload, 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	actual := expected
	actual.SHA256 = "new"
	if err := verifyManifest(path, actual); err == nil {
		t.Fatal("verifyManifest returned nil for a different object hash")
	}
}

func TestValidateRequiredSpecsRejectsMissingStatsMap(t *testing.T) {
	spec := requiredCollectionSpecForTest()
	delete(spec.Maps, "agentshield_stats_map")

	err := validateRequiredSpecs(spec)
	if err == nil || !strings.Contains(err.Error(), "agentshield_stats_map") {
		t.Fatalf("validateRequiredSpecs error = %v, want missing stats map", err)
	}
}

func TestValidateRequiredSpecsRejectsIncompatibleScopeMap(t *testing.T) {
	spec := requiredCollectionSpecForTest()
	spec.Maps["agentshield_scope_map"].ValueSize = 4

	err := validateRequiredSpecs(spec)
	if err == nil || !strings.Contains(err.Error(), "incompatible layout") {
		t.Fatalf("validateRequiredSpecs error = %v, want incompatible scope map", err)
	}
}

func requiredCollectionSpecForTest() *ebpf.CollectionSpec {
	programs := make(map[string]*ebpf.ProgramSpec)
	for _, name := range []string{"agentshield_connect4", "agentshield_connect6", "agentshield_trace_execve", "agentshield_trace_openat"} {
		programs[name] = &ebpf.ProgramSpec{}
	}
	return &ebpf.CollectionSpec{
		Programs: programs,
		Maps: map[string]*ebpf.MapSpec{
			"agentshield_events": {},
			"agentshield_scope_map": {
				Type:       ebpf.Hash,
				KeySize:    8,
				ValueSize:  24,
				MaxEntries: 1024,
			},
			"agentshield_stats_map": {},
		},
	}
}
