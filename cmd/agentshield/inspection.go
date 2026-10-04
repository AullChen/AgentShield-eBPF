package main

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"

	"github.com/agentshield/agentshield-ebpf/internal/inspection"
)

// Inspection files are trusted administrator input, never workload mounts.
func readInspectionFile(path string) ([]byte, error) {
	if !filepath.IsAbs(path) {
		return nil, errors.New("inspection file requires an absolute path")
	}
	parent := filepath.Dir(path)
	resolved, err := filepath.EvalSymlinks(parent)
	if err != nil || resolved != parent {
		return nil, errors.New("untrusted inspection directory")
	}
	directory, err := os.Stat(parent)
	if err != nil || !directory.IsDir() {
		return nil, errors.New("inspection directory unavailable")
	}
	if runtime.GOOS != "windows" && directory.Mode().Perm()&0o077 != 0 {
		return nil, errors.New("inspection directory must be owner-only")
	}
	if err := validateReadTokenOwner(directory); err != nil {
		return nil, err
	}
	expected, err := os.Lstat(path)
	if err != nil || !expected.Mode().IsRegular() {
		return nil, errors.New("inspection file must be regular and not a symlink")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, errors.New("inspection file unavailable")
	}
	defer file.Close()
	actual, err := file.Stat()
	if err != nil || !os.SameFile(expected, actual) || !actual.Mode().IsRegular() {
		return nil, errors.New("inspection file identity changed")
	}
	if runtime.GOOS != "windows" && actual.Mode().Perm()&0o077 != 0 {
		return nil, errors.New("inspection file must be owner-only")
	}
	if err := validateReadTokenOwner(actual); err != nil {
		return nil, err
	}
	data, err := io.ReadAll(io.LimitReader(file, inspection.MaxBody+1))
	if err != nil || len(data) > inspection.MaxBody {
		return nil, errors.New("inspection file exceeds limit")
	}
	return data, nil
}
