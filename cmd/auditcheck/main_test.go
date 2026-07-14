package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/agentshield/agentshield-ebpf/internal/events"
)

func TestAnalyzeAcceptsDay14Evidence(t *testing.T) {
	input := encodeEvents(t,
		events.KernelEvent{
			JSONSchemaVersion: events.JSONSchemaVersion,
			SchemaVersion:     events.WireSchemaVersion,
			EventType:         events.EventTypeFileOpen,
			EventTypeName:     "file_open",
			ActionResult:      events.ActionResultNone,
			ActionResultName:  "none",
			Data:              "/tmp/agentshield-day14-file",
		},
		events.KernelEvent{
			JSONSchemaVersion: events.JSONSchemaVersion,
			SchemaVersion:     events.WireSchemaVersion,
			EventType:         events.EventTypeExecAttempt,
			EventTypeName:     "exec_attempt",
			ActionResult:      events.ActionResultNone,
			ActionResultName:  "none",
			Argv:              []string{"/bin/echo", "", "agentshield-day14-exec", strings.Repeat("x", 31)},
			Truncated:         true,
		},
	)

	summary, err := analyze(input, "agentshield-day14-file", "agentshield-day14-exec")
	if err != nil {
		t.Fatalf("analyze returned error: %v", err)
	}
	if !summary.FileMarkerMatched || !summary.ExecMarkerMatched || !summary.EmptyArgPreserved || !summary.TruncationSeen {
		t.Fatalf("summary did not pass all gates: %+v", summary)
	}
}

func TestAnalyzeRejectsSuccessClaimAtSyscallEntry(t *testing.T) {
	input := encodeEvents(t, events.KernelEvent{
		JSONSchemaVersion: events.JSONSchemaVersion,
		SchemaVersion:     events.WireSchemaVersion,
		EventType:         events.EventTypeFileOpen,
		EventTypeName:     "file_open",
		ActionResult:      events.ActionResultAllowed,
		ActionResultName:  "allowed",
		Data:              "/tmp/marker",
	})

	_, err := analyze(input, "marker", "exec")
	if err == nil || !strings.Contains(err.Error(), "want none") {
		t.Fatalf("analyze error = %v, want attempt result error", err)
	}
}

func TestAnalyzeRejectsMissingEmptyArg(t *testing.T) {
	input := encodeEvents(t,
		events.KernelEvent{JSONSchemaVersion: 2, SchemaVersion: 2, EventType: events.EventTypeFileOpen, EventTypeName: "file_open", Data: "file"},
		events.KernelEvent{JSONSchemaVersion: 2, SchemaVersion: 2, EventType: events.EventTypeExecAttempt, EventTypeName: "exec_attempt", Argv: []string{"/bin/echo", "exec"}, Truncated: true},
	)

	_, err := analyze(input, "file", "exec")
	if err == nil || !strings.Contains(err.Error(), "empty argv") {
		t.Fatalf("analyze error = %v, want empty argv error", err)
	}
}

func encodeEvents(t *testing.T, values ...events.KernelEvent) *bytes.Buffer {
	t.Helper()
	var buffer bytes.Buffer
	encoder := json.NewEncoder(&buffer)
	for _, value := range values {
		if err := encoder.Encode(value); err != nil {
			t.Fatalf("Encode: %v", err)
		}
	}
	return &buffer
}
