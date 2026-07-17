package main

import (
	"bytes"
	"encoding/json"
	"net/netip"
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

func TestAnalyzePreservesTruncationAcrossDuplicateMarkerEvents(t *testing.T) {
	input := encodeEvents(t,
		events.KernelEvent{JSONSchemaVersion: 2, SchemaVersion: 2, EventType: events.EventTypeFileOpen, EventTypeName: "file_open", Data: "file"},
		events.KernelEvent{JSONSchemaVersion: 2, SchemaVersion: 2, EventType: events.EventTypeExecAttempt, EventTypeName: "exec_attempt", Argv: []string{"", "exec"}, Truncated: true},
		events.KernelEvent{JSONSchemaVersion: 2, SchemaVersion: 2, EventType: events.EventTypeExecAttempt, EventTypeName: "exec_attempt", Argv: []string{"", "exec"}, Truncated: false},
	)

	summary, err := analyze(input, "file", "exec")
	if err != nil {
		t.Fatalf("analyze returned error: %v", err)
	}
	if !summary.TruncationSeen {
		t.Fatal("TruncationSeen = false, want true when any marker event was truncated")
	}
}

func TestAnalyzeAcceptsIPv4AndIPv6Coverage(t *testing.T) {
	input := encodeEvents(t,
		events.KernelEvent{JSONSchemaVersion: 2, SchemaVersion: 2, EventType: events.EventTypeFileOpen, EventTypeName: "file_open", Data: "file"},
		events.KernelEvent{JSONSchemaVersion: 2, SchemaVersion: 2, EventType: events.EventTypeExecAttempt, EventTypeName: "exec_attempt", Argv: []string{"/bin/echo", "", "exec", strings.Repeat("x", 31)}, Truncated: true},
		events.KernelEvent{JSONSchemaVersion: 2, SchemaVersion: 2, EventType: events.EventTypeNetConnect, EventTypeName: "net_connect", DestinationIP: "127.0.0.1", DestinationPort: 18080},
		events.KernelEvent{JSONSchemaVersion: 2, SchemaVersion: 2, EventType: events.EventTypeNetConnect, EventTypeName: "net_connect", DestinationIP: "::1", DestinationPort: 18080},
	)
	ipv4 := netip.MustParseAddrPort("127.0.0.1:18080")
	ipv6 := netip.MustParseAddrPort("[::1]:18080")

	summary, err := analyze(input, "file", "exec", ipv4, ipv6)
	if err != nil {
		t.Fatalf("analyze returned error: %v", err)
	}
	if !summary.NetworkDestinationsMatched[ipv4.String()] || !summary.NetworkDestinationsMatched[ipv6.String()] {
		t.Fatalf("network matches = %v, want both destinations", summary.NetworkDestinationsMatched)
	}
}

func TestAnalyzeRejectsMissingNetworkCoverage(t *testing.T) {
	input := encodeEvents(t,
		events.KernelEvent{JSONSchemaVersion: 2, SchemaVersion: 2, EventType: events.EventTypeFileOpen, EventTypeName: "file_open", Data: "file"},
		events.KernelEvent{JSONSchemaVersion: 2, SchemaVersion: 2, EventType: events.EventTypeExecAttempt, EventTypeName: "exec_attempt", Argv: []string{"", "exec"}, Truncated: true},
	)

	_, err := analyze(input, "file", "exec", netip.MustParseAddrPort("127.0.0.1:18080"))
	if err == nil || !strings.Contains(err.Error(), "no net_connect") {
		t.Fatalf("analyze error = %v, want missing network error", err)
	}
}

func TestAnalyzeRequiresNonNegativeReceiptClocks(t *testing.T) {
	input := encodeEvents(t, events.KernelEvent{
		JSONSchemaVersion:         2,
		SchemaVersion:             2,
		EventType:                 events.EventTypeFileOpen,
		EventTypeName:             "file_open",
		Data:                      "file",
		KernelMonotonicNS:         20,
		ServerReceivedMonotonicNS: 10,
		ServerReceivedUnixNS:      30,
	})

	_, err := analyzeWithOptions(input, "file", "exec", analysisOptions{RequireReceiptClocks: true})
	if err == nil || !strings.Contains(err.Error(), "negative ring-buffer receipt latency") {
		t.Fatalf("analyze error = %v, want negative latency error", err)
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
