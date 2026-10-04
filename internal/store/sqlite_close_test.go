package store

import (
	"errors"
	"path/filepath"
	"testing"
)

func TestSQLiteAppendAfterCloseReturnsError(t *testing.T) {
	database, err := OpenSQLite(filepath.Join(t.TempDir(), "closed.db"), SQLiteOptions{})
	if errors.Is(err, ErrSQLiteUnavailable) {
		t.Skip(err)
	}
	if err != nil {
		t.Fatal(err)
	}
	if err := database.Close(); err != nil {
		t.Fatal(err)
	}
	if err := database.AppendBatch([]Record{{ID: "after-close"}}); err == nil {
		t.Fatal("closed database accepted append")
	}
	if _, err := database.Count(); err == nil {
		t.Fatal("closed database accepted count")
	}
}
