package store

import (
	"bytes"
	"context"
	"errors"
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
	if err := writer.Close(context.Background()); err != nil {
		t.Fatalf("Close: %v", err)
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
