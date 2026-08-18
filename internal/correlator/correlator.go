package correlator

import (
	"errors"
	"sort"
	"strings"
)

type AttributionStatus string

const (
	AttributionExact   AttributionStatus = "exact"
	AttributionStale   AttributionStatus = "stale"
	AttributionUnknown AttributionStatus = "unknown"
)

type Attribution struct {
	RunID     string            `json:"run_id,omitempty"`
	RunStatus string            `json:"run_status,omitempty"`
	Status    AttributionStatus `json:"status"`
}

type ResolveRun func(instanceID, scopeCookie, serverMonotonicNS uint64) Attribution

type KernelEvent struct {
	EventID           string
	InstanceID        uint64
	ScopeCookie       uint64
	ServerMonotonicNS uint64
	PID               uint32
	TGID              uint32
	EventType         string
	ToolName          string
}

type Checkpoint struct {
	CheckpointID      string
	RunID             string
	ServerMonotonicNS uint64
	ClientUnixNS      uint64
	Sequence          uint64
	Type              string
	Phase             string
	ToolName          string
	PID               uint32
	TGID              uint32
}

type Factor struct {
	Name   string `json:"name"`
	Points int    `json:"points"`
	Detail string `json:"detail"`
}

type Candidate struct {
	CheckpointID string   `json:"checkpoint_id"`
	Score        int      `json:"score"`
	DeltaNS      int64    `json:"delta_ns"`
	Factors      []Factor `json:"factors"`
}

type Result struct {
	EventID            string      `json:"event_id"`
	Attribution        Attribution `json:"attribution"`
	SelectedCheckpoint string      `json:"selected_checkpoint_id,omitempty"`
	Confidence         int         `json:"confidence"`
	Conflict           bool        `json:"conflict"`
	Candidates         []Candidate `json:"candidates"`
	CorrelationStatus  string      `json:"correlation_status"`
	AuthoritativeClock string      `json:"authoritative_clock"`
}

type Options struct {
	BeforeWindowNS uint64
	AfterWindowNS  uint64
	MinimumScore   int
}

type Correlator struct {
	resolve ResolveRun
	options Options
}

func New(resolve ResolveRun, options Options) (*Correlator, error) {
	if resolve == nil {
		return nil, errors.New("Run resolver is required")
	}
	if options.BeforeWindowNS == 0 {
		options.BeforeWindowNS = 1500 * 1_000_000
	}
	if options.AfterWindowNS == 0 {
		options.AfterWindowNS = 5000 * 1_000_000
	}
	if options.MinimumScore == 0 {
		options.MinimumScore = 25
	}
	if options.BeforeWindowNS > 60*1_000_000_000 || options.AfterWindowNS > 60*1_000_000_000 ||
		options.MinimumScore < 1 || options.MinimumScore > 100 {
		return nil, errors.New("correlation options are invalid")
	}
	return &Correlator{resolve: resolve, options: options}, nil
}

func (correlator *Correlator) Correlate(event KernelEvent, checkpoints []Checkpoint) Result {
	result := Result{EventID: event.EventID, AuthoritativeClock: "server_monotonic_ns", CorrelationStatus: "unmatched"}
	if event.EventID == "" || event.InstanceID == 0 || event.ScopeCookie == 0 || event.ServerMonotonicNS == 0 {
		result.Attribution = Attribution{Status: AttributionUnknown}
		result.CorrelationStatus = "invalid_event"
		return result
	}
	result.Attribution = correlator.resolve(event.InstanceID, event.ScopeCookie, event.ServerMonotonicNS)
	if result.Attribution.Status != AttributionExact || result.Attribution.RunID == "" {
		result.CorrelationStatus = "unattributed"
		return result
	}
	for _, checkpoint := range checkpoints {
		if checkpoint.RunID != result.Attribution.RunID || checkpoint.CheckpointID == "" || checkpoint.ServerMonotonicNS == 0 {
			continue
		}
		delta, inWindow := boundedDelta(event.ServerMonotonicNS, checkpoint.ServerMonotonicNS, correlator.options)
		if !inWindow {
			continue
		}
		candidate := scoreCandidate(event, checkpoint, delta, correlator.options)
		if candidate.Score >= correlator.options.MinimumScore {
			result.Candidates = append(result.Candidates, candidate)
		}
	}
	sort.Slice(result.Candidates, func(i, j int) bool {
		if result.Candidates[i].Score != result.Candidates[j].Score {
			return result.Candidates[i].Score > result.Candidates[j].Score
		}
		if absolute(result.Candidates[i].DeltaNS) != absolute(result.Candidates[j].DeltaNS) {
			return absolute(result.Candidates[i].DeltaNS) < absolute(result.Candidates[j].DeltaNS)
		}
		return result.Candidates[i].CheckpointID < result.Candidates[j].CheckpointID
	})
	if len(result.Candidates) == 0 {
		return result
	}
	best := result.Candidates[0]
	result.Confidence = best.Score
	if len(result.Candidates) > 1 && result.Candidates[1].Score == best.Score &&
		absolute(result.Candidates[1].DeltaNS) == absolute(best.DeltaNS) {
		result.Conflict = true
		result.CorrelationStatus = "ambiguous"
		return result
	}
	result.SelectedCheckpoint = best.CheckpointID
	result.CorrelationStatus = "matched"
	return result
}

func scoreCandidate(event KernelEvent, checkpoint Checkpoint, delta int64, options Options) Candidate {
	candidate := Candidate{CheckpointID: checkpoint.CheckpointID, DeltaNS: delta}
	add := func(name string, points int, detail string) {
		candidate.Factors = append(candidate.Factors, Factor{Name: name, Points: points, Detail: detail})
		candidate.Score += points
	}
	if event.TGID != 0 && checkpoint.TGID == event.TGID {
		add("same_tgid", 35, "checkpoint and event share TGID")
	} else if event.PID != 0 && checkpoint.PID == event.PID {
		add("same_pid", 30, "checkpoint and event share PID")
	}
	if event.ToolName != "" && strings.EqualFold(event.ToolName, checkpoint.ToolName) {
		add("tool_name", 25, "normalized tool names match")
	}
	if compatible(event.EventType, checkpoint.Type) {
		add("semantic_phase", 15, "checkpoint type is compatible with event class")
	}
	window := options.AfterWindowNS
	if delta < 0 {
		window = options.BeforeWindowNS
	}
	closeness := 25
	if window != 0 {
		closeness = 5 + int((uint64(window)-uint64(absolute(delta)))*20/window)
	}
	add("server_monotonic_proximity", closeness, "same-host server monotonic time window")
	if candidate.Score > 100 {
		candidate.Score = 100
	}
	return candidate
}

func compatible(eventType, checkpointType string) bool {
	eventType = strings.ToLower(eventType)
	switch checkpointType {
	case "tool_planned", "tool_started", "tool_finished":
		return strings.Contains(eventType, "file") || strings.Contains(eventType, "exec") || strings.Contains(eventType, "net")
	case "llm_request", "llm_response":
		return strings.Contains(eventType, "net")
	default:
		return false
	}
}

func boundedDelta(eventNS, checkpointNS uint64, options Options) (int64, bool) {
	if eventNS >= checkpointNS {
		difference := eventNS - checkpointNS
		if difference > options.AfterWindowNS || difference > uint64(^uint64(0)>>1) {
			return 0, false
		}
		return int64(difference), true
	}
	difference := checkpointNS - eventNS
	if difference > options.BeforeWindowNS || difference > uint64(^uint64(0)>>1) {
		return 0, false
	}
	return -int64(difference), true
}

func absolute(value int64) uint64 {
	if value < 0 {
		return uint64(-(value + 1)) + 1
	}
	return uint64(value)
}
