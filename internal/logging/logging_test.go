package logging

import "testing"

func TestNewAcceptsKnownLevels(t *testing.T) {
	levels := []string{"", "debug", "info", "warn", "warning", "error"}
	for _, level := range levels {
		if _, err := New(level); err != nil {
			t.Fatalf("New(%q) returned error: %v", level, err)
		}
	}
}

func TestNewRejectsUnknownLevel(t *testing.T) {
	if _, err := New("verbose"); err == nil {
		t.Fatal("New(\"verbose\") returned nil error")
	}
}
