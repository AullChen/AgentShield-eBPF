package api

import (
	"fmt"
	"os"
)

func validateSocketDirectory(mode os.FileMode, ownerUID, effectiveUID uint32) error {
	if !mode.IsDir() {
		return fmt.Errorf("management socket parent is not a directory")
	}
	if mode.Perm()&0o077 != 0 {
		return fmt.Errorf("management socket directory permissions %04o allow group or other access", mode.Perm())
	}
	if ownerUID != effectiveUID {
		return fmt.Errorf("management socket directory owner %d does not match effective UID %d", ownerUID, effectiveUID)
	}
	return nil
}
