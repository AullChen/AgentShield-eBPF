package stream

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	defaultCapacity    = 10_000
	defaultMaxAge      = 5 * time.Minute
	defaultClientQueue = 64
	maxPayloadBytes    = 64 << 10
)

var (
	ErrInvalidEvent = errors.New("invalid stream event")
	ErrHubClosed    = errors.New("stream hub is closed")
	ErrSequenceFull = errors.New("stream sequence is exhausted")
)

type Event struct {
	ID                string
	Type              string
	Source            string
	RunID             string
	Severity          string
	EventType         string
	ServerMonotonicNS uint64
	ServerUnixNS      uint64
	Audit             bool
	Payload           json.RawMessage
}

type Message struct {
	SchemaVersion     string          `json:"schema_version"`
	Sequence          string          `json:"sequence"`
	ResumeCursor      string          `json:"resume_cursor"`
	ID                string          `json:"id"`
	Type              string          `json:"type"`
	Source            string          `json:"source,omitempty"`
	RunID             string          `json:"run_id,omitempty"`
	Severity          string          `json:"severity,omitempty"`
	EventType         string          `json:"event_type,omitempty"`
	ServerMonotonicNS string          `json:"server_monotonic_ns"`
	ServerUnixNS      string          `json:"server_unix_ns"`
	Audit             bool            `json:"audit,omitempty"`
	Payload           json.RawMessage `json:"payload"`

	createdAt time.Time
}

type Filter struct {
	RunID        string
	Severity     string
	EventType    string
	IncludeAudit bool
}

type HubOptions struct {
	Capacity    int
	MaxAge      time.Duration
	ClientQueue int
	SnapshotURL string
	Now         func() time.Time
}

type Hub struct {
	mu          sync.Mutex
	now         func() time.Time
	capacity    int
	maxAge      time.Duration
	clientQueue int
	snapshotURL string
	latest      uint64
	history     []Message
	nextID      uint64
	clients     map[uint64]*subscription
	closed      bool
	done        chan struct{}
}

type subscription struct {
	id       uint64
	filter   Filter
	messages chan Message
	overflow chan struct{}
}

func NewHub(options HubOptions) (*Hub, error) {
	if options.Capacity == 0 {
		options.Capacity = defaultCapacity
	}
	if options.MaxAge == 0 {
		options.MaxAge = defaultMaxAge
	}
	if options.ClientQueue == 0 {
		options.ClientQueue = defaultClientQueue
	}
	if options.SnapshotURL == "" {
		options.SnapshotURL = "/api/v1/snapshot"
	}
	if options.Now == nil {
		options.Now = time.Now
	}
	if options.Capacity < 1 || options.Capacity > defaultCapacity ||
		options.MaxAge < time.Second || options.MaxAge > defaultMaxAge ||
		options.ClientQueue < 1 || options.ClientQueue > 1024 ||
		!strings.HasPrefix(options.SnapshotURL, "/") {
		return nil, errors.New("invalid stream hub options")
	}
	return &Hub{
		now:         options.Now,
		capacity:    options.Capacity,
		maxAge:      options.MaxAge,
		clientQueue: options.ClientQueue,
		snapshotURL: options.SnapshotURL,
		clients:     make(map[uint64]*subscription),
		done:        make(chan struct{}),
	}, nil
}

func (hub *Hub) Publish(event Event) (Message, error) {
	if err := validateEvent(event); err != nil {
		return Message{}, err
	}

	hub.mu.Lock()
	defer hub.mu.Unlock()
	if hub.closed {
		return Message{}, ErrHubClosed
	}
	if hub.latest == ^uint64(0) {
		return Message{}, ErrSequenceFull
	}

	now := hub.now()
	hub.pruneLocked(now)
	hub.latest++
	sequence := strconv.FormatUint(hub.latest, 10)
	message := Message{
		SchemaVersion:     "1",
		Sequence:          sequence,
		ResumeCursor:      sequence,
		ID:                event.ID,
		Type:              event.Type,
		Source:            event.Source,
		RunID:             event.RunID,
		Severity:          event.Severity,
		EventType:         event.EventType,
		ServerMonotonicNS: strconv.FormatUint(event.ServerMonotonicNS, 10),
		ServerUnixNS:      strconv.FormatUint(event.ServerUnixNS, 10),
		Audit:             event.Audit,
		Payload:           append(json.RawMessage(nil), event.Payload...),
		createdAt:         now,
	}
	hub.history = append(hub.history, message)
	if excess := len(hub.history) - hub.capacity; excess > 0 {
		copy(hub.history, hub.history[excess:])
		hub.history = hub.history[:len(hub.history)-excess]
	}

	for id, client := range hub.clients {
		if !matches(client.filter, message) {
			continue
		}
		select {
		case client.messages <- message:
		default:
			close(client.overflow)
			delete(hub.clients, id)
		}
	}
	published := message
	published.Payload = append(json.RawMessage(nil), message.Payload...)
	return published, nil
}

// Snapshot returns the newest retained messages within independent count and
// byte budgets. The hub lock protects only selection of immutable message
// references; payload copies happen after release so readers cannot stall
// Publish while allocating large snapshots.
func (hub *Hub) Snapshot(ctx context.Context, filter Filter, limit, maxBytes int) ([]Message, error) {
	if ctx == nil || limit < 1 || limit > defaultCapacity || maxBytes < maxPayloadBytes || maxBytes > 16<<20 {
		return nil, errors.New("invalid stream snapshot options")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	hub.mu.Lock()
	hub.pruneLocked(hub.now())
	messages := make([]Message, 0, min(limit, len(hub.history)))
	payloadBytes := 0
	for index := len(hub.history) - 1; index >= 0 && len(messages) < limit; index-- {
		message := hub.history[index]
		if !matches(filter, message) {
			continue
		}
		if payloadBytes+len(message.Payload) > maxBytes {
			break
		}
		payloadBytes += len(message.Payload)
		messages = append(messages, message)
	}
	hub.mu.Unlock()

	slices.Reverse(messages)
	for index := range messages {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		messages[index].Payload = append(json.RawMessage(nil), messages[index].Payload...)
	}
	return messages, nil
}

func validateEvent(event Event) error {
	if event.ID == "" || len(event.ID) > 128 || event.Type == "" || len(event.Type) > 64 || len(event.Source) > 32 ||
		len(event.RunID) > 128 || len(event.Severity) > 32 || len(event.EventType) > 64 ||
		len(event.Payload) == 0 || len(event.Payload) > maxPayloadBytes || !json.Valid(event.Payload) {
		return ErrInvalidEvent
	}
	return nil
}

func matches(filter Filter, message Message) bool {
	return (filter.RunID == "" || filter.RunID == message.RunID) &&
		(filter.Severity == "" || filter.Severity == message.Severity) &&
		(filter.EventType == "" || filter.EventType == message.EventType) &&
		(filter.IncludeAudit || !message.Audit)
}

func (hub *Hub) subscribe(cursor uint64, cursorSet bool, filter Filter) ([]Message, *subscription, *Message) {
	hub.mu.Lock()
	defer hub.mu.Unlock()

	hub.pruneLocked(hub.now())
	if hub.closed {
		message := hub.resyncLocked("server_shutdown", cursor, hub.latest+1)
		return nil, nil, &message
	}
	oldest := hub.latest + 1
	if len(hub.history) > 0 {
		oldest, _ = strconv.ParseUint(hub.history[0].Sequence, 10, 64)
	}
	expired := cursor > hub.latest
	if cursorSet && !expired {
		if len(hub.history) == 0 {
			expired = cursor < hub.latest
		} else {
			expired = cursor < oldest-1
		}
	}
	if cursorSet && expired {
		reason := "cursor_expired"
		if cursor > hub.latest {
			reason = "cursor_ahead"
		}
		message := hub.resyncLocked(reason, cursor, oldest)
		return nil, nil, &message
	}
	if !cursorSet {
		cursor = hub.latest
	}

	initial := make([]Message, 0)
	for _, message := range hub.history {
		sequence, _ := strconv.ParseUint(message.Sequence, 10, 64)
		if sequence > cursor && matches(filter, message) {
			initial = append(initial, message)
		}
	}
	hub.nextID++
	client := &subscription{
		id:       hub.nextID,
		filter:   filter,
		messages: make(chan Message, hub.clientQueue),
		overflow: make(chan struct{}),
	}
	hub.clients[client.id] = client
	return initial, client, nil
}

func (hub *Hub) unsubscribe(client *subscription) {
	if client == nil {
		return
	}
	hub.mu.Lock()
	delete(hub.clients, client.id)
	hub.mu.Unlock()
}

func (hub *Hub) Close() {
	hub.mu.Lock()
	if !hub.closed {
		hub.closed = true
		close(hub.done)
		hub.clients = make(map[uint64]*subscription)
	}
	hub.mu.Unlock()
}

func (hub *Hub) resync(reason string, cursor uint64) Message {
	hub.mu.Lock()
	defer hub.mu.Unlock()
	hub.pruneLocked(hub.now())
	oldest := hub.latest + 1
	if len(hub.history) > 0 {
		oldest, _ = strconv.ParseUint(hub.history[0].Sequence, 10, 64)
	}
	return hub.resyncLocked(reason, cursor, oldest)
}

func (hub *Hub) resyncLocked(reason string, requested, oldest uint64) Message {
	payload, _ := json.Marshal(struct {
		Reason          string `json:"reason"`
		RequestedCursor string `json:"requested_cursor"`
		OldestCursor    string `json:"oldest_cursor"`
		LatestCursor    string `json:"latest_cursor"`
		SnapshotURL     string `json:"snapshot_url"`
	}{
		Reason:          reason,
		RequestedCursor: strconv.FormatUint(requested, 10),
		OldestCursor:    strconv.FormatUint(oldest, 10),
		LatestCursor:    strconv.FormatUint(hub.latest, 10),
		SnapshotURL:     hub.snapshotURL,
	})
	latest := strconv.FormatUint(hub.latest, 10)
	return Message{
		SchemaVersion:     "1",
		Sequence:          latest,
		ResumeCursor:      latest,
		ID:                fmt.Sprintf("resync-%d", hub.latest),
		Type:              "resync_required",
		ServerMonotonicNS: "0",
		ServerUnixNS:      "0",
		Payload:           payload,
		createdAt:         hub.now(),
	}
}

func (hub *Hub) pruneLocked(now time.Time) {
	cutoff := now.Add(-hub.maxAge)
	first := 0
	for first < len(hub.history) && hub.history[first].createdAt.Before(cutoff) {
		first++
	}
	if first > 0 {
		copy(hub.history, hub.history[first:])
		hub.history = hub.history[:len(hub.history)-first]
	}
}
