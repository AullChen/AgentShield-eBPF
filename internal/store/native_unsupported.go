//go:build !windows && !cgo

package store

func openNative(string) (sqliteNative, error) { return nil, ErrSQLiteUnavailable }
