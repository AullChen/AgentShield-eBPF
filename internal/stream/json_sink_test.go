package stream

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func TestJSONLineSinkRedactsBeforePublish(t *testing.T) {
	hub, err := NewHub(HubOptions{})
	if err != nil {
		t.Fatal(err)
	}
	_, client, resync := hub.subscribe(0, false, Filter{IncludeAudit: true})
	if resync != nil {
		t.Fatal("unexpected resync")
	}
	defer hub.unsubscribe(client)
	var published PublishedRecord
	sink, err := NewJSONLineSink(hub, JSONLineSinkOptions{
		RunID: "run-1", SensitiveValues: []string{"literal-secret"},
		OnPublished: func(record PublishedRecord) { published = record },
	})
	if err != nil {
		t.Fatal(err)
	}
	line := `{"schema_version":2,"event_type_name":"exec_attempt","action_name":"audit","action_result_name":"none","server_received_monotonic_ns":"9007199254740994","server_received_unix_ns":"1800000000000000000","prompt":"do not expose","argv":["--token=abcd1234","literal-secret"]}` + "\n"
	if _, err := sink.Write([]byte(line[:40])); err != nil {
		t.Fatal(err)
	}
	if _, err := sink.Write([]byte(line[40:])); err != nil {
		t.Fatal(err)
	}
	message := <-client.messages
	if message.RunID != "run-1" || message.Source != "kernel_fact" || message.EventType != "exec_attempt" || !message.Audit {
		t.Fatalf("message metadata = %#v", message)
	}
	if bytes.Contains(message.Payload, []byte("do not expose")) || bytes.Contains(message.Payload, []byte("abcd1234")) || bytes.Contains(message.Payload, []byte("literal-secret")) {
		t.Fatalf("payload was not redacted: %s", message.Payload)
	}
	if bytes.Count(message.Payload, []byte("[REDACTED]")) != 3 {
		t.Fatalf("redacted payload = %s", message.Payload)
	}
	if !published.KernelFact || published.PolicyDecision || published.RunID != "run-1" {
		t.Fatalf("published metadata = %#v", published)
	}
}

func TestJSONLineSinkDropsOversizedLineWithoutBackpressure(t *testing.T) {
	hub, _ := NewHub(HubOptions{})
	var reported error
	sink, _ := NewJSONLineSink(hub, JSONLineSinkOptions{RunID: "run-1", OnError: func(err error) { reported = err }})
	input := []byte(strings.Repeat("x", maxJSONLineBytes+1) + "\n")
	written, err := sink.Write(input)
	if err != nil || written != len(input) || reported == nil {
		t.Fatalf("Write = %d, %v; report=%v", written, err, reported)
	}
}

func TestJSONLineSinkPublishesPolicyDecision(t *testing.T) {
	hub, _ := NewHub(HubOptions{})
	_, client, _ := hub.subscribe(0, false, Filter{IncludeAudit: true})
	defer hub.unsubscribe(client)
	var published PublishedRecord
	sink, _ := NewJSONLineSink(hub, JSONLineSinkOptions{RunID: "run-1", OnPublished: func(record PublishedRecord) { published = record }})
	record := map[string]any{
		"record_type": "policy_decision", "server_received_monotonic_ns": "12",
		"server_received_unix_ns": "13", "final": map[string]any{"requested_action": "alert"},
	}
	encoded, _ := json.Marshal(record)
	encoded = append(encoded, '\n')
	_, _ = sink.Write(encoded)
	message := <-client.messages
	if message.Type != "policy_decision" || message.Source != "policy_decision" || !published.PolicyDecision || published.KernelFact {
		t.Fatalf("message=%#v published=%#v", message, published)
	}
}
