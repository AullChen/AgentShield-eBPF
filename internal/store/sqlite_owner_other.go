//go:build !linux

package store

import "os"

func validateSQLiteDirectoryOwner(os.FileInfo) error { return nil }
