package store

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestSQLitePersistsSanitizedRecordsInWALDatabase(t *testing.T) {
	path := filepath.Join(t.TempDir(), "evidence.db")
	database, err := OpenSQLite(path, SQLiteOptions{SoftLimitBytes: 1 << 20, HardLimitBytes: 2 << 20})
	if errors.Is(err, ErrSQLiteUnavailable) {
		t.Skip(err)
	}
	if err != nil {
		t.Fatalf("OpenSQLite: %v", err)
	}
	writer, err := NewWriter(database, WriterOptions{
		QueueCapacity: 8, RecentCapacity: 8, RecentBytes: 32 << 10, BatchSize: 1,
		FlushInterval: time.Millisecond, RetryInterval: time.Millisecond,
		Redactor: NewRedactor([]string{"literal-super-secret"}),
	})
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}
	if !writer.Submit(testRecord("one", "Bearer abcdefgh literal-super-secret")) {
		t.Fatal("Submit rejected")
	}
	waitFor(t, func() bool { count, _ := database.Count(); return count == 1 })
	if err := writer.Close(context.Background()); err != nil {
		t.Fatalf("Writer.Close: %v", err)
	}
	if err := database.Close(); err != nil {
		t.Fatalf("SQLite.Close: %v", err)
	}

	contents, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if !bytes.HasPrefix(contents, []byte("SQLite format 3\x00")) {
		t.Fatal("database is not SQLite")
	}
	for _, path := range []string{path, path + "-wal"} {
		contents, _ := os.ReadFile(path)
		if bytes.Contains(contents, []byte("literal-super-secret")) || bytes.Contains(contents, []byte("abcdefgh")) {
			t.Fatalf("raw secret persisted in %s", path)
		}
	}
}

func TestSQLiteDoesNotReportCommittedBatchAsFailedWhenMaintenanceFails(t *testing.T) {
	path := filepath.Join(t.TempDir(), "full.db")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	database := &maintenanceFailNative{path: path}
	store := &SQLite{database: database, path: path, softLimit: 1, hardLimit: 2}
	if err := store.AppendBatch([]Record{testRecord("committed", "safe")}); err != nil {
		t.Fatalf("committed batch reported failure: %v", err)
	}
	if database.transactions != 1 {
		t.Fatalf("transactions = %d, want 1", database.transactions)
	}
	if err := store.AppendBatch([]Record{testRecord("next", "safe")}); err == nil {
		t.Fatal("next batch ignored unresolved capacity maintenance failure")
	}
	if database.transactions != 1 {
		t.Fatalf("failed maintenance allowed another transaction: %d", database.transactions)
	}
	if err := store.Close(); err == nil {
		t.Fatal("Close ignored unresolved capacity maintenance failure")
	}
}

func TestSQLiteTreatsRecordIDsAsIdempotencyKeys(t *testing.T) {
	path := filepath.Join(t.TempDir(), "idempotent.db")
	database, err := OpenSQLite(path, SQLiteOptions{SoftLimitBytes: 1 << 20, HardLimitBytes: 2 << 20})
	if errors.Is(err, ErrSQLiteUnavailable) {
		t.Skip(err)
	}
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	first := testRecord("same-id", "first")
	second := testRecord("same-id", "must not replace first")
	if err := database.AppendBatch([]Record{first, second}); err != nil {
		t.Fatalf("duplicate batch: %v", err)
	}
	if err := database.AppendBatch([]Record{second}); err != nil {
		t.Fatalf("duplicate retry: %v", err)
	}
	count, err := database.Count()
	if err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("record count = %d, want 1", count)
	}
}

func TestSQLiteCapacityPruningRetainsRecordsNearSoftLimit(t *testing.T) {
	path := filepath.Join(t.TempDir(), "capacity.db")
	database, err := OpenSQLite(path, SQLiteOptions{SoftLimitBytes: 1 << 20, HardLimitBytes: 2 << 20})
	if errors.Is(err, ErrSQLiteUnavailable) {
		t.Skip(err)
	}
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	for start := 0; start < 300; start += 25 {
		records := make([]Record, 0, 25)
		for index := start; index < start+25; index++ {
			record := testRecord(fmt.Sprintf("capacity-%03d", index), strings.Repeat("x", 4096))
			record.ServerMonotonicNS = uint64(index + 1)
			record.Labels = map[string]string{"payload": strings.Repeat("y", 1024)}
			records = append(records, record)
		}
		if err := database.AppendBatch(records); err != nil {
			t.Fatalf("AppendBatch %d: %v", start, err)
		}
	}
	count, err := database.Count()
	if err != nil {
		t.Fatal(err)
	}
	if count < 128 || count >= 300 {
		t.Fatalf("retained records = %d, want bounded history near the soft limit", count)
	}
	database.mu.Lock()
	usage, err := database.usageLocked()
	database.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	if usage > database.hardLimit {
		t.Fatalf("capacity usage = %d, hard limit = %d", usage, database.hardLimit)
	}
}

func TestWriterCircuitBreakerDoesNotBlockAndReportsGap(t *testing.T) {
	backend := &flakyBackend{failures: 2}
	var diagnostics bytes.Buffer
	writer, err := NewWriter(backend, WriterOptions{
		QueueCapacity: 2, RecentCapacity: 1, RecentBytes: 2048, BatchSize: 1,
		FlushInterval: time.Millisecond, RetryInterval: 100 * time.Millisecond,
		Redactor: NewRedactor([]string{"do-not-log"}), Diagnostics: &diagnostics,
	})
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}
	start := time.Now()
	for index := 0; index < 100; index++ {
		writer.Submit(testRecord(string(rune('a'+index%26)), "do-not-log"))
	}
	if time.Since(start) > 100*time.Millisecond {
		t.Fatal("Submit blocked on failing backend")
	}
	waitFor(t, func() bool { return writer.Diagnostics().CircuitOpen })
	waitFor(t, func() bool {
		diagnostic := writer.Diagnostics()
		return diagnostic.StoreDrops > 0 || diagnostic.QueueDrops > 0
	})
	if strings.Contains(diagnostics.String(), "do-not-log") {
		t.Fatal("diagnostic leaked record content")
	}
	if err := writer.Close(context.Background()); err == nil {
		t.Fatal("Close reported success with unpersisted records")
	}
}

func TestWriterRecoveryFlushesBoundedRecentBuffer(t *testing.T) {
	backend := &flakyBackend{failures: 1}
	writer, err := NewWriter(backend, WriterOptions{
		QueueCapacity: 8, RecentCapacity: 8, RecentBytes: 32 << 10, BatchSize: 1,
		FlushInterval: time.Millisecond, RetryInterval: 2 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}
	writer.Submit(testRecord("recover", "safe"))
	waitFor(t, func() bool { return backend.count() == 1 })
	waitFor(t, func() bool { return !writer.Diagnostics().CircuitOpen })
	if err := writer.Close(context.Background()); err != nil {
		t.Fatalf("Close: %v", err)
	}
}

func TestWriterCloseRejectsNewRecordsAndDrainsAcceptedRecords(t *testing.T) {
	backend := &blockingBackend{started: make(chan struct{}), release: make(chan struct{})}
	writer, err := NewWriter(backend, WriterOptions{
		QueueCapacity: 8, RecentCapacity: 8, RecentBytes: 32 << 10, BatchSize: 1,
		FlushInterval: time.Millisecond, RetryInterval: time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !writer.Submit(testRecord("accepted", "safe")) {
		t.Fatal("initial Submit rejected")
	}
	<-backend.started
	closed := make(chan error, 1)
	go func() { closed <- writer.Close(context.Background()) }()
	waitFor(t, func() bool {
		writer.submitMu.RLock()
		defer writer.submitMu.RUnlock()
		return writer.closing
	})
	if writer.Submit(testRecord("late", "safe")) {
		t.Fatal("Submit accepted after Close began")
	}
	close(backend.release)
	if err := <-closed; err != nil {
		t.Fatalf("Close: %v", err)
	}
	if backend.count() != 1 {
		t.Fatalf("persisted records = %d, want 1", backend.count())
	}
}

func TestRedactorUsesStructuredLabelKeysAndCredentialForms(t *testing.T) {
	record := testRecord("redaction", "AWS_SECRET_ACCESS_KEY=abcd1234 --api-key=sk_live_123")
	record.Labels = map[string]string{
		"password":  "hunter2",
		"X-Api-Key": "key-value",
		"tool":      "safe",
	}
	redacted, err := NewRedactor(nil).Apply(record)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(redacted.Summary, "abcd1234") || strings.Contains(redacted.Summary, "sk_live_123") {
		t.Fatalf("summary retained credentials: %q", redacted.Summary)
	}
	if redacted.Labels["password"] != "[REDACTED]" || redacted.Labels["X-Api-Key"] != "[REDACTED]" {
		t.Fatalf("sensitive labels = %#v", redacted.Labels)
	}
	if redacted.Labels["tool"] != "safe" {
		t.Fatalf("safe label changed: %#v", redacted.Labels)
	}
}

func TestRecordValidationRejectsNULBeforeQueueing(t *testing.T) {
	record := testRecord("nul", "safe\x00truncated")
	if _, err := NewRedactor(nil).Apply(record); err == nil {
		t.Fatal("record containing NUL was accepted")
	}
	record = testRecord("nul-label", "safe")
	record.Labels["tool"] = "safe\x00truncated"
	if _, err := NewRedactor(nil).Apply(record); err == nil {
		t.Fatal("label containing NUL was accepted")
	}
}

func testRecord(id, summary string) Record {
	return Record{ID: id, RecordType: "kernel_event", RunID: "run-1", Source: SourceKernelFact,
		ServerMonotonicNS: 100, ServerUnixNS: 200, InstanceID: 11, ScopeCookie: 22,
		Severity: "high", Summary: summary, Labels: map[string]string{"tool": summary}}
}

func waitFor(t *testing.T, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if condition() {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("condition not satisfied")
}

type flakyBackend struct {
	mu       sync.Mutex
	failures int
	records  []Record
}

type blockingBackend struct {
	mu      sync.Mutex
	started chan struct{}
	release chan struct{}
	records []Record
}

type maintenanceFailNative struct {
	transactions int
	path         string
}

func (database *maintenanceFailNative) Exec(statement string) error {
	if strings.HasPrefix(statement, "BEGIN IMMEDIATE;") {
		database.transactions++
		return os.WriteFile(database.path, []byte("over limit"), 0o600)
	}
	if strings.HasPrefix(statement, "DELETE FROM evidence_records") {
		return errors.New("maintenance failed")
	}
	return nil
}

func (database *maintenanceFailNative) ScalarInt64(query string) (int64, error) {
	switch query {
	case "PRAGMA page_count;", "SELECT count(*) FROM evidence_records;":
		if database.transactions == 0 {
			return 0, nil
		}
		return 1, nil
	case "PRAGMA page_size;":
		return 10, nil
	case "PRAGMA freelist_count;":
		return 0, nil
	default:
		return 0, errors.New("unexpected scalar query")
	}
}
func (*maintenanceFailNative) Close() error { return nil }

func (backend *blockingBackend) AppendBatch(records []Record) error {
	close(backend.started)
	<-backend.release
	backend.mu.Lock()
	backend.records = append(backend.records, records...)
	backend.mu.Unlock()
	return nil
}

func (backend *blockingBackend) count() int {
	backend.mu.Lock()
	defer backend.mu.Unlock()
	return len(backend.records)
}

func (backend *flakyBackend) AppendBatch(records []Record) error {
	backend.mu.Lock()
	defer backend.mu.Unlock()
	if backend.failures > 0 {
		backend.failures--
		return errors.New("SQLITE_BUSY confidential payload")
	}
	backend.records = append(backend.records, records...)
	return nil
}
func (backend *flakyBackend) count() int {
	backend.mu.Lock()
	defer backend.mu.Unlock()
	return len(backend.records)
}
