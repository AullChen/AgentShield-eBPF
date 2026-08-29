package store

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
)

const schema = `
PRAGMA journal_mode=WAL;
PRAGMA synchronous=NORMAL;
PRAGMA busy_timeout=250;
PRAGMA foreign_keys=ON;
CREATE TABLE IF NOT EXISTS evidence_records (
  id TEXT PRIMARY KEY,
  record_type TEXT NOT NULL,
  run_id TEXT NOT NULL,
  source TEXT NOT NULL,
  server_monotonic_ns TEXT NOT NULL,
  server_unix_ns TEXT NOT NULL,
  instance_id TEXT NOT NULL,
  scope_cookie TEXT NOT NULL,
  severity TEXT NOT NULL,
  summary TEXT NOT NULL,
  labels_json TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS evidence_records_run_time
ON evidence_records(run_id, server_monotonic_ns);
CREATE TABLE IF NOT EXISTS agent_runs (run_id TEXT PRIMARY KEY, data_json TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS checkpoints (checkpoint_id TEXT PRIMARY KEY, data_json TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS kernel_events (event_id TEXT PRIMARY KEY, data_json TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS policy_hits (hit_id TEXT PRIMARY KEY, data_json TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS evidence_chains (chain_id TEXT PRIMARY KEY, data_json TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS policies (policy_id TEXT PRIMARY KEY, data_json TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS system_diagnostics (diagnostic_id TEXT PRIMARY KEY, data_json TEXT NOT NULL);
`

type SQLiteOptions struct {
	SoftLimitBytes int64
	HardLimitBytes int64
}

type SQLite struct {
	mu        sync.Mutex
	database  sqliteNative
	path      string
	softLimit int64
	hardLimit int64
}

func OpenSQLite(path string, options SQLiteOptions) (*SQLite, error) {
	if path == "" || path == ":memory:" {
		return nil, errors.New("a filesystem SQLite path is required")
	}
	cleaned, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("resolve SQLite path: %w", err)
	}
	if options.SoftLimitBytes == 0 {
		options.SoftLimitBytes = 100 << 20
	}
	if options.HardLimitBytes == 0 {
		options.HardLimitBytes = 128 << 20
	}
	if options.SoftLimitBytes < 1<<20 || options.HardLimitBytes < options.SoftLimitBytes {
		return nil, errors.New("SQLite capacity limits are invalid")
	}
	if err := os.MkdirAll(filepath.Dir(cleaned), 0o700); err != nil {
		return nil, fmt.Errorf("create SQLite directory: %w", err)
	}
	database, err := openNative(cleaned)
	if err != nil {
		return nil, err
	}
	store := &SQLite{database: database, path: cleaned, softLimit: options.SoftLimitBytes, hardLimit: options.HardLimitBytes}
	pageLimit := options.HardLimitBytes / 4096
	if err := database.Exec(schema + "\nPRAGMA max_page_count=" + strconv.FormatInt(pageLimit, 10) + ";"); err != nil {
		_ = database.Close()
		return nil, fmt.Errorf("initialize SQLite: %w", err)
	}
	return store, nil
}

func (store *SQLite) AppendBatch(records []Record) error {
	if len(records) == 0 {
		return nil
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	// Capacity maintenance can fail independently of a prior successful
	// transaction. Retry it before accepting another batch so callers never
	// retry records that were already committed.
	if store.sizeLocked() > store.softLimit {
		if err := store.pruneLocked(); err != nil {
			return err
		}
	}
	var statement strings.Builder
	statement.WriteString("BEGIN IMMEDIATE;")
	for _, record := range records {
		if err := record.validate(); err != nil {
			return err
		}
		statement.WriteString("INSERT INTO evidence_records VALUES(")
		values := []string{
			record.ID, record.RecordType, record.RunID, string(record.Source),
			strconv.FormatUint(record.ServerMonotonicNS, 10), strconv.FormatUint(record.ServerUnixNS, 10),
			strconv.FormatUint(record.InstanceID, 10), strconv.FormatUint(record.ScopeCookie, 10),
			record.Severity, record.Summary, labelsJSON(record.Labels),
		}
		for index, value := range values {
			if index != 0 {
				statement.WriteByte(',')
			}
			statement.WriteString(sqlQuote(value))
		}
		statement.WriteString(");")
	}
	statement.WriteString("COMMIT;")
	if err := store.database.Exec(statement.String()); err != nil {
		_ = store.database.Exec("ROLLBACK;")
		return err
	}
	if size := store.sizeLocked(); size > store.softLimit {
		// The records above are durable regardless of maintenance outcome.
		// A failed prune is retried and reported before the next transaction,
		// or by Close when no further writes arrive.
		_ = store.pruneLocked()
	}
	return nil
}

func (store *SQLite) Count() (int64, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	return store.database.ScalarInt64("SELECT count(*) FROM evidence_records;")
}

func (store *SQLite) Close() error {
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.database == nil {
		return nil
	}
	var maintenanceErr error
	if store.sizeLocked() > store.softLimit {
		maintenanceErr = store.pruneLocked()
	}
	_ = store.database.Exec("PRAGMA wal_checkpoint(TRUNCATE);")
	closeErr := store.database.Close()
	store.database = nil
	return errors.Join(maintenanceErr, closeErr)
}

func (store *SQLite) pruneLocked() error {
	for attempts := 0; attempts < 20 && store.sizeLocked() > store.softLimit; attempts++ {
		if err := store.database.Exec(`DELETE FROM evidence_records WHERE id IN (
SELECT id FROM evidence_records ORDER BY
CASE severity WHEN 'critical' THEN 3 WHEN 'high' THEN 2 ELSE 1 END ASC,
CAST(server_monotonic_ns AS INTEGER) ASC LIMIT 256);`); err != nil {
			return fmt.Errorf("prune SQLite: %w", err)
		}
		if err := store.database.Exec("PRAGMA wal_checkpoint(PASSIVE);"); err != nil {
			return fmt.Errorf("checkpoint SQLite WAL: %w", err)
		}
	}
	if store.sizeLocked() > store.hardLimit {
		return errors.New("SQLite hard capacity remains exceeded after pruning")
	}
	return nil
}

func (store *SQLite) sizeLocked() int64 {
	var total int64
	for _, path := range []string{store.path, store.path + "-wal", store.path + "-shm"} {
		if info, err := os.Stat(path); err == nil {
			total += info.Size()
		}
	}
	return total
}

func sqlQuote(value string) string { return "'" + strings.ReplaceAll(value, "'", "''") + "'" }
