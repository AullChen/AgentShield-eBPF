//go:build !linux

package main

import "os"

func validateReadTokenOwner(os.FileInfo) error { return nil }
