package main

import (
	"bytes"
	"strings"
	"testing"
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
