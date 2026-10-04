package inspection

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

const testRun = "0123456789abcdef0123456789abcdef"

func testChecker(t *testing.T) (*Checker, *[]Decision) {
	t.Helper()
	decisions := []Decision{}
	checker, err := New(Config{Routes: []Route{{ID: "model", Kind: "model"}}, RequestsPerRun: 32, Concurrency: 2, SensitiveFiles: []string{"known"}}, Options{
		Authenticate: func(token string) (string, error) {
			if token != "trusted" {
				return "", errors.New("bad token")
			}
			return testRun, nil
		},
		ActiveRun: func(id string) bool { return id == testRun },
		Audit:     func(decision Decision) error { decisions = append(decisions, decision); return nil },
	}, func(string) ([]byte, error) { return []byte("synthetic-private-value"), nil })
	if err != nil {
		t.Fatal(err)
	}
	return checker, &decisions
}
func digest(data string) string {
	hash := sha256.Sum256([]byte(data))
	return hex.EncodeToString(hash[:])
}
func approve(t *testing.T, c *Checker, route, body string) {
	t.Helper()
	if err := c.Approve(Approval{RunID: testRun, RouteID: route, SHA256: digest(body), ExpiresAt: c.now().Add(time.Minute)}); err != nil {
		t.Fatal(err)
	}
}
func check(c *Checker, route, body string) *httptest.ResponseRecorder {
	r := httptest.NewRequest("POST", "/gateway/v1/check/"+route, strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Authorization", "Bearer trusted")
	w := httptest.NewRecorder()
	c.ServeHTTP(w, r)
	return w
}

func TestExactSingleUseApprovalAndLocalOnly(t *testing.T) {
	c, _ := testChecker(t)
	body := `{"messages":[{"content":"approved source fragment"}]}`
	if w := check(c, "model", body); w.Code != 403 || !strings.Contains(w.Body.String(), "approval_required") {
		t.Fatal(w)
	}
	approve(t, c, "model", body)
	if w := check(c, "model", body+" "); w.Code != 403 {
		t.Fatal("approval accepted changed bytes")
	}
	w := check(c, "model", body)
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"forwarded":false`) || !strings.Contains(w.Body.String(), `"executed":false`) || !strings.Contains(w.Body.String(), `"mode":"local_only"`) {
		t.Fatal(w)
	}
	if check(c, "model", body).Code != 403 {
		t.Fatal("approval reused")
	}
}

func TestSecretsAndMalformedBodiesCannotBeApproved(t *testing.T) {
	c, decisions := testChecker(t)
	for _, body := range []string{
		`{"content":"synthetic-private-value"}`, `{"content":"synthetic-private-\u0076alue"}`,
		`{"api_key":"synthetic-key"}`, `{"content":"-----BEGIN RSA PRIVATE KEY-----"}`,
		`{"x":1,"x":2}`, `{"x":1} {}`, `[]`, `{"x":"` + string([]byte{0xff}) + `"}`,
		`{"x":` + strings.Repeat("[", 34) + `0` + strings.Repeat("]", 34) + `}`,
	} {
		approve(t, c, "model", body)
		if check(c, "model", body).Code < 400 {
			t.Fatal("approved unsafe body")
		}
	}
	if check(c, "model", `{"content":"`+strings.Repeat("x", MaxBody)+`"}`).Code != 413 {
		t.Fatal("accepted oversized body")
	}
	data, _ := json.Marshal(decisions)
	if strings.Contains(string(data), "synthetic-") || strings.Contains(string(data), "PRIVATE KEY") {
		t.Fatal("audit stored request contents")
	}
}

func TestExpiryBudgetAndFailClosedAudit(t *testing.T) {
	c, _ := testChecker(t)
	c.limit = 3
	body := `{"question":"hello"}`
	approve(t, c, "model", body)
	now := c.now()
	c.now = func() time.Time { return now.Add(2 * time.Minute) }
	if check(c, "model", body).Code != 403 {
		t.Fatal("expired approval accepted")
	}
	for i := 0; i < 2; i++ {
		approve(t, c, "model", body)
		if check(c, "model", body).Code != 200 {
			t.Fatal("budget denied too early")
		}
	}
	approve(t, c, "model", body)
	if check(c, "model", body).Code != 429 {
		t.Fatal("budget exceeded")
	}
	c, _ = testChecker(t)
	c.options.Audit = func(Decision) error { return errors.New("storage unavailable") }
	if check(c, "model", body).Code != 503 {
		t.Fatal("audit failure was not fail-closed")
	}
	if c.Approve(Approval{RunID: testRun, RouteID: "model", SHA256: digest(body), ExpiresAt: c.now().Add(time.Minute)}) == nil {
		t.Fatal("issued unaudited approval")
	}
}

func TestDeniedRequestsConsumeBoundedBudget(t *testing.T) {
	c, decisions := testChecker(t)
	c.limit = 1
	if check(c, "model", `{"secret":"test"}`).Code != 403 {
		t.Fatal("sensitive body accepted")
	}
	if check(c, "model", `{}`).Code != 429 {
		t.Fatal("denied request did not consume budget")
	}
	count := len(*decisions)
	for i := 0; i < 5; i++ {
		if check(c, "model", `{}`).Code != 429 {
			t.Fatal("exhausted budget allowed more requests")
		}
	}
	if len(*decisions) != count {
		t.Fatal("exhausted requests flooded audit storage")
	}
}

func TestOriginAuthAndManagementSeparation(t *testing.T) {
	c, _ := testChecker(t)
	for _, change := range []func(*httptest.ResponseRecorder){
		func(w *httptest.ResponseRecorder) {
			r := httptest.NewRequest("POST", "/gateway/v1/check/model", strings.NewReader(`{}`))
			r.Header.Set("Origin", "https://evil.test")
			c.ServeHTTP(w, r)
		},
		func(w *httptest.ResponseRecorder) {
			c.ServeHTTP(w, httptest.NewRequest("POST", "/gateway/v1/check/model", strings.NewReader(`{}`)))
		},
		func(w *httptest.ResponseRecorder) {
			c.ServeHTTP(w, httptest.NewRequest("POST", "/api/v1/inspection/approvals", strings.NewReader(`{}`)))
		},
	} {
		w := httptest.NewRecorder()
		change(w)
		if w.Code < 400 {
			t.Fatal("accepted untrusted request")
		}
	}
	if c.Approve(Approval{RunID: strings.Repeat("b", 32), RouteID: "model", SHA256: digest(`{}`), ExpiresAt: time.Now().Add(time.Minute)}) == nil {
		t.Fatal("cross-Run approval accepted")
	}
}

func TestConcurrentApprovalConsumedOnce(t *testing.T) {
	c, _ := testChecker(t)
	c.options.Audit = func(Decision) error { return nil }
	body := `{"question":"hello"}`
	approve(t, c, "model", body)
	var group sync.WaitGroup
	codes := make(chan int, 2)
	for i := 0; i < 2; i++ {
		group.Add(1)
		go func() { defer group.Done(); codes <- check(c, "model", body).Code }()
	}
	group.Wait()
	close(codes)
	allowed := 0
	for code := range codes {
		if code == 200 {
			allowed++
		}
	}
	if allowed != 1 {
		t.Fatal("approval consumed more than once")
	}
}
