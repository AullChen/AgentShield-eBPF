package main

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestLaunchEnvelope(t *testing.T) {
	valid := `{"run_id":"0123456789abcdef0123456789abcdef","ingest_token":"token","command":["/usr/bin/python3","main.py"],"timeout_seconds":30,"environment":{"LANG":"en_US.UTF-8"}}`
	r, err := decodeLaunch(strings.NewReader(valid))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(strings.Join(environment(r), "\n"), "LANG=") != 1 {
		t.Fatal("duplicate environment")
	}
	for _, input := range []string{
		strings.Replace(valid, "/usr/bin/python3", "python3", 1),
		strings.Replace(valid, `"LANG"`, `"LD_PRELOAD"`, 1),
		strings.Replace(valid, `:30`, `:901`, 1), valid + `{}`, strings.Repeat("x", 16385),
	} {
		if _, err := decodeLaunch(strings.NewReader(input)); err == nil {
			t.Fatal("accepted invalid envelope")
		}
	}
}

func TestRelayAuthorityAndRoutes(t *testing.T) {
	calls := 0
	transport := roundTripFunc(func(r *http.Request) (*http.Response, error) {
		calls++
		if r.URL.Host != "localhost" || r.Header.Get("Authorization") != "Bearer trusted" || r.Header.Get("X-API-Key") != "" {
			t.Fatal("forwarded client authority")
		}
		return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(`{}`))}, nil
	})
	handler := relayHandler(launchRequest{RunID: "own", IngestToken: "trusted"}, transport)
	for _, path := range []string{"/api/v1/agents/register", "/ingest/v1/runs/other/checkpoints", "/gateway/v1/model?url=evil", "/arbitrary"} {
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, httptest.NewRequest("POST", path, strings.NewReader(`{}`)))
		if response.Code < 400 {
			t.Fatal("accepted forbidden route")
		}
	}
	if calls != 0 {
		t.Fatal("contacted host on rejected route")
	}
	r := httptest.NewRequest("POST", "/gateway/v1/model", strings.NewReader(`{}`))
	r.Header.Set("Authorization", "Bearer attacker")
	r.Header.Set("X-API-Key", "secret")
	handler.ServeHTTP(httptest.NewRecorder(), r)
	if calls != 1 {
		t.Fatal("expected one authorized relay call")
	}
}
