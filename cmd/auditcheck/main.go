package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/agentshield/agentshield-ebpf/internal/events"
)

type acceptanceSummary struct {
	SchemaVersion     int            `json:"schema_version"`
	TotalEvents       int            `json:"total_events"`
	EventCounts       map[string]int `json:"event_counts"`
	FileMarkerMatched bool           `json:"file_marker_matched"`
	ExecMarkerMatched bool           `json:"exec_marker_matched"`
	EmptyArgPreserved bool           `json:"empty_arg_preserved"`
	TruncationSeen    bool           `json:"truncation_seen"`
}

func main() {
	if err := run(os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintf(os.Stderr, "auditcheck: %v\n", err)
		os.Exit(1)
	}
}

func run(args []string, out io.Writer) error {
	var inputPath string
	var fileMarker string
	var execMarker string

	flags := flag.NewFlagSet("auditcheck", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	flags.StringVar(&inputPath, "input", "", "path to audit JSON Lines")
	flags.StringVar(&fileMarker, "file-marker", "", "unique file path fragment expected in a file event")
	flags.StringVar(&execMarker, "exec-marker", "", "unique argv value expected in an exec event")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if inputPath == "" || fileMarker == "" || execMarker == "" {
		return errors.New("--input, --file-marker, and --exec-marker are required")
	}
	if flags.NArg() != 0 {
		return fmt.Errorf("unexpected arguments: %q", flags.Args())
	}

	input, err := os.Open(inputPath)
	if err != nil {
		return fmt.Errorf("open input: %w", err)
	}
	defer input.Close()

	summary, err := analyze(input, fileMarker, execMarker)
	if err != nil {
		return err
	}
	encoder := json.NewEncoder(out)
	encoder.SetIndent("", "  ")
	return encoder.Encode(summary)
}

func analyze(input io.Reader, fileMarker, execMarker string) (acceptanceSummary, error) {
	summary := acceptanceSummary{
		SchemaVersion: 1,
		EventCounts:   make(map[string]int),
	}
	scanner := bufio.NewScanner(input)
	scanner.Buffer(make([]byte, 4096), 1024*1024)
	line := 0
	for scanner.Scan() {
		line++
		if strings.TrimSpace(scanner.Text()) == "" {
			continue
		}
		var event events.KernelEvent
		if err := json.Unmarshal(scanner.Bytes(), &event); err != nil {
			return acceptanceSummary{}, fmt.Errorf("decode line %d: %w", line, err)
		}
		if event.JSONSchemaVersion != events.JSONSchemaVersion || event.SchemaVersion != events.WireSchemaVersion {
			return acceptanceSummary{}, fmt.Errorf("line %d has incompatible JSON/wire schema %d/%d", line, event.JSONSchemaVersion, event.SchemaVersion)
		}
		summary.TotalEvents++
		summary.EventCounts[event.EventTypeName]++

		switch event.EventType {
		case events.EventTypeFileOpen:
			if strings.Contains(event.Data, fileMarker) {
				if event.ActionResult != events.ActionResultNone {
					return acceptanceSummary{}, fmt.Errorf("file marker event action_result=%s, want none", event.ActionResultName)
				}
				summary.FileMarkerMatched = true
			}
		case events.EventTypeExecAttempt:
			markerIndex := -1
			for index, arg := range event.Argv {
				if arg == execMarker {
					markerIndex = index
					break
				}
			}
			if markerIndex >= 0 {
				if event.ActionResult != events.ActionResultNone {
					return acceptanceSummary{}, fmt.Errorf("exec marker event action_result=%s, want none", event.ActionResultName)
				}
				summary.ExecMarkerMatched = true
				summary.TruncationSeen = event.Truncated
				if markerIndex > 0 && event.Argv[markerIndex-1] == "" {
					summary.EmptyArgPreserved = true
				}
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return acceptanceSummary{}, fmt.Errorf("read input: %w", err)
	}

	if !summary.FileMarkerMatched {
		return acceptanceSummary{}, fmt.Errorf("no file_open event matched %q", fileMarker)
	}
	if !summary.ExecMarkerMatched {
		return acceptanceSummary{}, fmt.Errorf("no exec_attempt argv matched %q", execMarker)
	}
	if !summary.EmptyArgPreserved {
		return acceptanceSummary{}, errors.New("exec marker was not preceded by the expected legal empty argv slot")
	}
	if !summary.TruncationSeen {
		return acceptanceSummary{}, errors.New("exec marker event did not report expected truncation")
	}
	return summary, nil
}
