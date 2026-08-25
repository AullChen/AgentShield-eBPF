package stream

import (
	"bufio"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

const testReadToken = "read-only-test-token-123456789"

func TestAuthenticatedWebSocketReceivesFilteredEvent(t *testing.T) {
	hub, handler := testStream(t, HubOptions{})
	server := httptest.NewServer(handler.Routes())
	defer server.Close()

	connection, reader := dialWebSocket(t, server.URL, "/api/v1/stream?run_id=run-1&severity=high", "Bearer "+testReadToken)
	defer connection.Close()
	if _, err := hub.Publish(testEvent("ignored", "run-2", "high")); err != nil {
		t.Fatal(err)
	}
	wanted, err := hub.Publish(testEvent("wanted", "run-1", "high"))
	if err != nil {
		t.Fatal(err)
	}
	got := readMessage(t, connection, reader)
	if got.ID != "wanted" || got.Sequence != wanted.Sequence || got.ResumeCursor != wanted.Sequence {
		t.Fatalf("received %#v, want event %#v", got, wanted)
	}
	if got.ServerMonotonicNS != "18446744073709551614" || got.ServerUnixNS != "18446744073709551613" {
		t.Fatalf("u64 fields lost precision: %#v", got)
	}
}

func TestSnapshotReturnsNewestMatchingMessagesWithoutSharingPayload(t *testing.T) {
	hub, err := NewHub(HubOptions{})
	if err != nil {
		t.Fatal(err)
	}
	for _, event := range []Event{
		testEvent("first", "run-1", "high"),
		testEvent("other", "run-2", "high"),
		testEvent("second", "run-1", "high"),
		testEvent("third", "run-1", "high"),
	} {
		if _, err := hub.Publish(event); err != nil {
			t.Fatal(err)
		}
	}
	messages, err := hub.Snapshot(Filter{RunID: "run-1", IncludeAudit: true}, 2)
	if err != nil {
		t.Fatal(err)
	}
	if len(messages) != 2 || messages[0].ID != "second" || messages[1].ID != "third" {
		t.Fatalf("snapshot = %#v", messages)
	}
	messages[0].Payload[0] = '['
	again, err := hub.Snapshot(Filter{RunID: "run-1", IncludeAudit: true}, 2)
	if err != nil {
		t.Fatal(err)
	}
	if string(again[0].Payload) != `{"summary":"redacted"}` {
		t.Fatalf("snapshot payload shared backing storage: %q", again[0].Payload)
	}
}

func TestTicketIsSingleUse(t *testing.T) {
	_, handler := testStream(t, HubOptions{})
	server := httptest.NewServer(handler.Routes())
	defer server.Close()

	request, _ := http.NewRequest(http.MethodPost, server.URL+"/api/v1/stream-ticket", nil)
	request.Header.Set("Authorization", "Bearer "+testReadToken)
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusCreated || response.Header.Get("Cache-Control") != "no-store" {
		t.Fatalf("ticket response = %d, cache=%q", response.StatusCode, response.Header.Get("Cache-Control"))
	}
	var body struct {
		Ticket string `json:"ticket"`
	}
	if err := json.NewDecoder(response.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	connection, _ := dialWebSocket(t, server.URL, "/api/v1/stream?ticket="+url.QueryEscape(body.Ticket), "")
	connection.Close()

	status := dialStatus(t, server.URL, "/api/v1/stream?ticket="+url.QueryEscape(body.Ticket), "")
	if status != http.StatusUnauthorized {
		t.Fatalf("reused ticket status = %d, want 401", status)
	}
}

func TestExpiredCursorRequiresSnapshot(t *testing.T) {
	hub, handler := testStream(t, HubOptions{Capacity: 2})
	for index := 0; index < 3; index++ {
		if _, err := hub.Publish(testEvent(fmt.Sprintf("event-%d", index), "run-1", "high")); err != nil {
			t.Fatal(err)
		}
	}
	server := httptest.NewServer(handler.Routes())
	defer server.Close()
	connection, reader := dialWebSocket(t, server.URL, "/api/v1/stream?cursor=0", "Bearer "+testReadToken)
	defer connection.Close()
	message := readMessage(t, connection, reader)
	if message.Type != "resync_required" {
		t.Fatalf("message type = %q", message.Type)
	}
	var payload struct {
		Reason       string `json:"reason"`
		OldestCursor string `json:"oldest_cursor"`
		LatestCursor string `json:"latest_cursor"`
		SnapshotURL  string `json:"snapshot_url"`
	}
	if err := json.Unmarshal(message.Payload, &payload); err != nil {
		t.Fatal(err)
	}
	if payload.Reason != "cursor_expired" || payload.OldestCursor != "2" || payload.LatestCursor != "3" || payload.SnapshotURL != "/api/v1/snapshot" {
		t.Fatalf("resync payload = %#v", payload)
	}
}

func TestSlowSubscriberCannotBlockPublisher(t *testing.T) {
	hub, _ := testStream(t, HubOptions{ClientQueue: 1})
	_, client, resync := hub.subscribe(0, false, Filter{IncludeAudit: true})
	if resync != nil {
		t.Fatal("unexpected resync")
	}
	defer hub.unsubscribe(client)

	done := make(chan struct{})
	go func() {
		for index := 0; index < 100; index++ {
			_, _ = hub.Publish(testEvent(fmt.Sprintf("event-%d", index), "run-1", "high"))
		}
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("slow subscriber blocked publisher")
	}
	select {
	case <-client.overflow:
	default:
		t.Fatal("slow subscriber did not receive overflow signal")
	}
}

func TestHistoryExpiresByAge(t *testing.T) {
	now := time.Unix(100, 0)
	hub, _ := testStream(t, HubOptions{MaxAge: time.Second, Now: func() time.Time { return now }})
	if _, err := hub.Publish(testEvent("old", "run-1", "high")); err != nil {
		t.Fatal(err)
	}
	now = now.Add(2 * time.Second)
	_, client, resync := hub.subscribe(0, true, Filter{IncludeAudit: true})
	if client != nil || resync == nil || resync.Type != "resync_required" {
		t.Fatalf("expired subscription = client %v, resync %#v", client, resync)
	}
}

func TestStreamRejectsMissingAuthentication(t *testing.T) {
	_, handler := testStream(t, HubOptions{})
	server := httptest.NewServer(handler.Routes())
	defer server.Close()
	if status := dialStatus(t, server.URL, "/api/v1/stream", ""); status != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", status)
	}
}

func TestHubCloseRejectsPublishAndSignalsSubscribers(t *testing.T) {
	hub, _ := NewHub(HubOptions{})
	_, client, _ := hub.subscribe(0, false, Filter{IncludeAudit: true})
	hub.Close()
	select {
	case <-hub.done:
	default:
		t.Fatal("hub close did not signal subscribers")
	}
	if _, err := hub.Publish(testEvent("after-close", "run-1", "high")); err != ErrHubClosed {
		t.Fatalf("Publish after close error = %v", err)
	}
	hub.unsubscribe(client)
}

func testStream(t *testing.T, options HubOptions) (*Hub, *Handler) {
	t.Helper()
	hub, err := NewHub(options)
	if err != nil {
		t.Fatal(err)
	}
	handler, err := NewHandler(hub, HandlerOptions{ReadToken: testReadToken, Now: options.Now})
	if err != nil {
		t.Fatal(err)
	}
	return hub, handler
}

func testEvent(id, runID, severity string) Event {
	return Event{
		ID: id, Type: "event", RunID: runID, Severity: severity, EventType: "exec_attempt",
		ServerMonotonicNS: ^uint64(0) - 1, ServerUnixNS: ^uint64(0) - 2,
		Payload: json.RawMessage(`{"summary":"redacted"}`),
	}
}

func dialWebSocket(t *testing.T, serverURL, path, authorization string) (net.Conn, *bufio.Reader) {
	t.Helper()
	parsed, err := url.Parse(serverURL)
	if err != nil {
		t.Fatal(err)
	}
	connection, err := net.Dial("tcp", parsed.Host)
	if err != nil {
		t.Fatal(err)
	}
	request := websocketRequest(parsed.Host, path, authorization)
	if _, err := io.WriteString(connection, request); err != nil {
		connection.Close()
		t.Fatal(err)
	}
	reader := bufio.NewReader(connection)
	response, err := http.ReadResponse(reader, &http.Request{Method: http.MethodGet})
	if err != nil {
		connection.Close()
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusSwitchingProtocols {
		connection.Close()
		t.Fatalf("websocket status = %d", response.StatusCode)
	}
	return connection, reader
}

func dialStatus(t *testing.T, serverURL, path, authorization string) int {
	t.Helper()
	parsed, _ := url.Parse(serverURL)
	connection, err := net.Dial("tcp", parsed.Host)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	if _, err := io.WriteString(connection, websocketRequest(parsed.Host, path, authorization)); err != nil {
		t.Fatal(err)
	}
	response, err := http.ReadResponse(bufio.NewReader(connection), &http.Request{Method: http.MethodGet})
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	return response.StatusCode
}

func websocketRequest(host, path, authorization string) string {
	request := "GET " + path + " HTTP/1.1\r\nHost: " + host + "\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: AAECAwQFBgcICQoLDA0ODw==\r\n"
	if authorization != "" {
		request += "Authorization: " + authorization + "\r\n"
	}
	return request + "\r\n"
}

func readMessage(t *testing.T, connection net.Conn, reader *bufio.Reader) Message {
	t.Helper()
	_ = connection.SetReadDeadline(time.Now().Add(5 * time.Second))
	first, err := reader.ReadByte()
	if err != nil {
		t.Fatal(err)
	}
	second, err := reader.ReadByte()
	if err != nil {
		t.Fatal(err)
	}
	if first&0x0f != 1 || second&0x80 != 0 {
		t.Fatalf("unexpected frame header %x %x", first, second)
	}
	length := uint64(second & 0x7f)
	if length == 126 {
		var value uint16
		if err := binary.Read(reader, binary.BigEndian, &value); err != nil {
			t.Fatal(err)
		}
		length = uint64(value)
	} else if length == 127 {
		if err := binary.Read(reader, binary.BigEndian, &length); err != nil {
			t.Fatal(err)
		}
	}
	payload := make([]byte, length)
	if _, err := io.ReadFull(reader, payload); err != nil {
		t.Fatal(err)
	}
	var message Message
	if err := json.Unmarshal(payload, &message); err != nil {
		t.Fatalf("decode frame %q: %v", strings.TrimSpace(string(payload)), err)
	}
	return message
}
