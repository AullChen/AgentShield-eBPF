package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestRunHelpReturnsSuccess(t *testing.T) {
	if err := run([]string{"--help"}); err != nil {
		t.Fatalf("run returned error: %v", err)
	}
}

func TestRunDoesNotOverwriteInput(t *testing.T) {
	input := filepath.Join(t.TempDir(), "events.h")
	const contents = "original source"
	if err := os.WriteFile(input, []byte(contents), 0o600); err != nil {
		t.Fatalf("write input: %v", err)
	}

	err := run([]string{"-out", input, "-package", "generated", input})
	if err == nil {
		t.Fatal("run returned nil error when output aliases input")
	}
	got, readErr := os.ReadFile(input)
	if readErr != nil {
		t.Fatalf("read input: %v", readErr)
	}
	if string(got) != contents {
		t.Fatalf("input contents = %q, want %q", got, contents)
	}
}

func TestRenderRejectsInvalidPackageName(t *testing.T) {
	names := []string{"bad-name", "123package", "package", "_"}
	for _, name := range names {
		t.Run(name, func(t *testing.T) {
			if _, err := render(name, nil); err == nil {
				t.Fatalf("render(%q) returned nil error", name)
			}
		})
	}
}

func TestRenderAcceptsValidPackageName(t *testing.T) {
	if _, err := render("generated", nil); err != nil {
		t.Fatalf("render returned error: %v", err)
	}
}
