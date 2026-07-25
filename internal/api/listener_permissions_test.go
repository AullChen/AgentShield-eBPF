package api

import (
	"os"
	"testing"
)

func TestValidateSocketDirectory(t *testing.T) {
	for _, test := range []struct {
		name         string
		mode         os.FileMode
		ownerUID     uint32
		effectiveUID uint32
		wantError    bool
	}{
		{name: "owner only", mode: os.ModeDir | 0o700, ownerUID: 1000, effectiveUID: 1000},
		{name: "group readable", mode: os.ModeDir | 0o750, ownerUID: 1000, effectiveUID: 1000, wantError: true},
		{name: "other searchable", mode: os.ModeDir | 0o701, ownerUID: 1000, effectiveUID: 1000, wantError: true},
		{name: "wrong owner", mode: os.ModeDir | 0o700, ownerUID: 1001, effectiveUID: 1000, wantError: true},
		{name: "not directory", mode: 0o600, ownerUID: 1000, effectiveUID: 1000, wantError: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			err := validateSocketDirectory(test.mode, test.ownerUID, test.effectiveUID)
			if (err != nil) != test.wantError {
				t.Fatalf("validateSocketDirectory() error = %v, wantError=%v", err, test.wantError)
			}
		})
	}
}
