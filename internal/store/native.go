package store

import "errors"

var ErrSQLiteUnavailable = errors.New("SQLite is unavailable on this build")

type sqliteNative interface {
	Exec(string) error
	ScalarInt64(string) (int64, error)
	Close() error
}
