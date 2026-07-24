package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/netip"
	"os"
	"strings"

	"github.com/agentshield/agentshield-ebpf/internal/events"
)

type acceptanceSummary struct {
	SchemaVersion              int             `json:"schema_version"`
	TotalEvents                int             `json:"total_events"`
	EventCounts                map[string]int  `json:"event_counts"`
	FileMarkerMatched          bool            `json:"file_marker_matched"`
	ExecMarkerMatched          bool            `json:"exec_marker_matched"`
	EmptyArgPreserved          bool            `json:"empty_arg_preserved"`
	TruncationSeen             bool            `json:"truncation_seen"`
	NetworkDestinationsMatched map[string]bool `json:"network_destinations_matched,omitempty"`
	CgroupID                   string          `json:"cgroup_id,omitempty"`
	InstanceID                 string          `json:"instance_id,omitempty"`
	ScopeCookie                string          `json:"scope_cookie,omitempty"`
}

type analysisOptions struct {
	RequiredDestinations []netip.AddrPort
	RequireReceiptClocks bool
	RequireScopeIdentity bool
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
	var ipv4Destination string
	var ipv6Destination string
	var requireReceiptClocks bool
	var requireScopeIdentity bool

	flags := flag.NewFlagSet("auditcheck", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	flags.StringVar(&inputPath, "input", "", "path to audit JSON Lines")
	flags.StringVar(&fileMarker, "file-marker", "", "unique file path fragment expected in a file event")
	flags.StringVar(&execMarker, "exec-marker", "", "unique argv value expected in an exec event")
	flags.StringVar(&ipv4Destination, "ipv4-destination", "", "optional IPv4 address:port required in a network event")
	flags.StringVar(&ipv6Destination, "ipv6-destination", "", "optional [IPv6]:port required in a network event")
	flags.BoolVar(&requireReceiptClocks, "require-receipt-clocks", false, "require calibrated kernel/receipt clock fields")
	flags.BoolVar(&requireScopeIdentity, "require-scope-identity", false, "require one consistent non-zero cgroup/instance/cookie tuple")
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

	var destinations []netip.AddrPort
	if ipv4Destination != "" {
		ipv4, err := netip.ParseAddrPort(ipv4Destination)
		if err != nil || !ipv4.Addr().Is4() {
			return fmt.Errorf("invalid --ipv4-destination %q", ipv4Destination)
		}
		destinations = append(destinations, ipv4)
	}
	if ipv6Destination != "" {
		ipv6, err := netip.ParseAddrPort(ipv6Destination)
		if err != nil || !ipv6.Addr().Is6() {
			return fmt.Errorf("invalid --ipv6-destination %q", ipv6Destination)
		}
		destinations = append(destinations, ipv6)
	}

	summary, err := analyzeWithOptions(input, fileMarker, execMarker, analysisOptions{
		RequiredDestinations: destinations,
		RequireReceiptClocks: requireReceiptClocks,
		RequireScopeIdentity: requireScopeIdentity,
	})
	if err != nil {
		return err
	}
	encoder := json.NewEncoder(out)
	encoder.SetIndent("", "  ")
	return encoder.Encode(summary)
}

func analyze(input io.Reader, fileMarker, execMarker string, requiredDestinations ...netip.AddrPort) (acceptanceSummary, error) {
	return analyzeWithOptions(input, fileMarker, execMarker, analysisOptions{RequiredDestinations: requiredDestinations})
}

func analyzeWithOptions(input io.Reader, fileMarker, execMarker string, options analysisOptions) (acceptanceSummary, error) {
	summary := acceptanceSummary{
		SchemaVersion: 1,
		EventCounts:   make(map[string]int),
	}
	if len(options.RequiredDestinations) > 0 {
		summary.NetworkDestinationsMatched = make(map[string]bool, len(options.RequiredDestinations))
		for _, destination := range options.RequiredDestinations {
			summary.NetworkDestinationsMatched[destination.String()] = false
		}
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
		if options.RequireReceiptClocks && event.EventType != events.EventTypeDropNotice {
			if event.KernelMonotonicNS == 0 || event.ServerReceivedMonotonicNS == 0 || event.ServerReceivedUnixNS == 0 {
				return acceptanceSummary{}, fmt.Errorf("line %d is missing required kernel/receipt clock fields", line)
			}
			if event.ServerReceivedMonotonicNS < event.KernelMonotonicNS {
				return acceptanceSummary{}, fmt.Errorf("line %d has negative ring-buffer receipt latency", line)
			}
		}
		if options.RequireScopeIdentity && event.EventType != events.EventTypeDropNotice {
			if event.CgroupID == 0 || event.InstanceID == 0 || event.ScopeCookie == 0 {
				return acceptanceSummary{}, fmt.Errorf("line %d is missing required scope identity", line)
			}
			cgroupID := fmt.Sprint(event.CgroupID)
			instanceID := fmt.Sprint(event.InstanceID)
			scopeCookie := fmt.Sprint(event.ScopeCookie)
			if summary.CgroupID == "" {
				summary.CgroupID = cgroupID
				summary.InstanceID = instanceID
				summary.ScopeCookie = scopeCookie
			} else if summary.CgroupID != cgroupID || summary.InstanceID != instanceID || summary.ScopeCookie != scopeCookie {
				return acceptanceSummary{}, fmt.Errorf("line %d has inconsistent scope identity", line)
			}
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
				summary.TruncationSeen = summary.TruncationSeen || event.Truncated
				if markerIndex > 0 && event.Argv[markerIndex-1] == "" {
					summary.EmptyArgPreserved = true
				}
			}
		case events.EventTypeNetConnect:
			address, err := netip.ParseAddr(event.DestinationIP)
			if err != nil {
				return acceptanceSummary{}, fmt.Errorf("line %d has invalid network destination %q", line, event.DestinationIP)
			}
			destination := netip.AddrPortFrom(address, event.DestinationPort).String()
			if _, required := summary.NetworkDestinationsMatched[destination]; required {
				if event.ActionResult != events.ActionResultNone {
					return acceptanceSummary{}, fmt.Errorf("network destination %s action_result=%s, want none", destination, event.ActionResultName)
				}
				summary.NetworkDestinationsMatched[destination] = true
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
	for destination, matched := range summary.NetworkDestinationsMatched {
		if !matched {
			return acceptanceSummary{}, fmt.Errorf("no net_connect event matched %s", destination)
		}
	}
	return summary, nil
}
