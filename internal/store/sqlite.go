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
	if err := validateSQLiteDirectory(filepath.Dir(cleaned)); err != nil {
		return nil, err
	}
	expected, err := os.Lstat(cleaned)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("inspect SQLite path: %w", err)
	}
	if err == nil && (expected.Mode()&os.ModeSymlink != 0 || !expected.Mode().IsRegular()) {
		return nil, errors.New("SQLite path must be a regular file, not a symbolic link")
	}
	database, err := openNative(cleaned)
	if err != nil {
		return nil, err
	}
	actual, err := os.Lstat(cleaned)
	if err != nil || actual.Mode()&os.ModeSymlink != 0 || !actual.Mode().IsRegular() ||
		(expected != nil && !os.SameFile(expected, actual)) {
		_ = database.Close()
		return nil, errors.New("SQLite file identity changed while opening")
	}
	if err := os.Chmod(cleaned, 0o600); err != nil {
		_ = database.Close()
		return nil, fmt.Errorf("restrict SQLite permissions: %w", err)
	}
	store := &SQLite{database: database, path: cleaned, softLimit: options.SoftLimitBytes, hardLimit: options.HardLimitBytes}
	pageLimit := options.HardLimitBytes / 4096
	if err := database.Exec(schema + "\nPRAGMA max_page_count=" + strconv.FormatInt(pageLimit, 10) + ";"); err != nil {
		_ = database.Close()
		return nil, fmt.Errorf("initialize SQLite: %w", err)
	}
	return store, nil
}

func validateSQLiteDirectory(path string) error {
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		return fmt.Errorf("resolve SQLite directory: %w", err)
	}
	if filepath.Clean(resolved) != filepath.Clean(path) {
		return errors.New("SQLite directory must not contain symbolic links")
	}
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("stat SQLite directory: %w", err)
	}
	if !info.IsDir() {
		return errors.New("SQLite parent is not a directory")
	}
	if err := validateSQLiteDirectoryOwner(info); err != nil {
		return err
	}
	return nil
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
	usage, err := store.usageLocked()
	if err != nil {
		return fmt.Errorf("measure SQLite capacity: %w", err)
	}
	if usage > store.softLimit {
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
		statement.WriteString(") ON CONFLICT(id) DO NOTHING;")
	}
	statement.WriteString("COMMIT;")
	if err := store.database.Exec(statement.String()); err != nil {
		_ = store.database.Exec("ROLLBACK;")
		return err
	}
	usage, err = store.usageLocked()
	if err == nil && usage > store.softLimit {
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
	if usage, err := store.usageLocked(); err != nil {
		maintenanceErr = fmt.Errorf("measure SQLite capacity: %w", err)
	} else if usage > store.softLimit {
		maintenanceErr = store.pruneLocked()
	}
	_ = store.database.Exec("PRAGMA wal_checkpoint(TRUNCATE);")
	closeErr := store.database.Close()
	store.database = nil
	return errors.Join(maintenanceErr, closeErr)
}

func (store *SQLite) pruneLocked() error {
	if err := store.database.Exec("PRAGMA wal_checkpoint(TRUNCATE);"); err != nil {
		return fmt.Errorf("checkpoint SQLite WAL: %w", err)
	}
	for attempts := 0; attempts < 20; attempts++ {
		usage, err := store.usageLocked()
		if err != nil {
			return fmt.Errorf("measure SQLite capacity: %w", err)
		}
		if usage <= store.softLimit {
			return nil
		}
		count, err := store.database.ScalarInt64("SELECT count(*) FROM evidence_records;")
		if err != nil {
			return fmt.Errorf("count SQLite records: %w", err)
		}
		if count == 0 {
			break
		}
		averageBytes := max(int64(1), usage/count)
		deleteCount := (usage - store.softLimit + averageBytes - 1) / averageBytes
		deleteCount = min(max(int64(1), deleteCount), min(count, int64(256)))
		statement := `DELETE FROM evidence_records WHERE id IN (
SELECT id FROM evidence_records ORDER BY
CASE severity WHEN 'critical' THEN 3 WHEN 'high' THEN 2 ELSE 1 END ASC,
CAST(server_monotonic_ns AS INTEGER) ASC LIMIT ` + strconv.FormatInt(deleteCount, 10) + `);`
		if err := store.database.Exec(statement); err != nil {
			return fmt.Errorf("prune SQLite: %w", err)
		}
		if err := store.database.Exec("PRAGMA wal_checkpoint(TRUNCATE);"); err != nil {
			return fmt.Errorf("checkpoint SQLite WAL: %w", err)
		}
	}
	usage, err := store.usageLocked()
	if err != nil {
		return fmt.Errorf("measure SQLite capacity: %w", err)
	}
	if usage > store.hardLimit {
		return errors.New("SQLite hard capacity remains exceeded after pruning")
	}
	return nil
}

func (store *SQLite) usageLocked() (int64, error) {
	pageCount, err := store.database.ScalarInt64("PRAGMA page_count;")
	if err != nil {
		return 0, err
	}
	freePages, err := store.database.ScalarInt64("PRAGMA freelist_count;")
	if err != nil {
		return 0, err
	}
	pageSize, err := store.database.ScalarInt64("PRAGMA page_size;")
	if err != nil {
		return 0, err
	}
	if pageCount < 0 || freePages < 0 || freePages > pageCount || pageSize < 1 {
		return 0, errors.New("SQLite returned invalid page accounting")
	}
	total := (pageCount - freePages) * pageSize
	for _, path := range []string{store.path + "-wal", store.path + "-shm"} {
		if info, err := os.Stat(path); err == nil {
			total += info.Size()
		}
	}
	return total, nil
}

func sqlQuote(value string) string { return "'" + strings.ReplaceAll(value, "'", "''") + "'" }
