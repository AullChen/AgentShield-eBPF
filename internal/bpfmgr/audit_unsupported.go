//go:build !linux

package bpfmgr

import (
	"context"
	"fmt"
	"io"
	"runtime"
)

func RunAudit(ctx context.Context, opts AuditOptions, out io.Writer) error {
	return fmt.Errorf("%w: kernel audit requires Linux, current platform is %s/%s", ErrUnsupported, runtime.GOOS, runtime.GOARCH)
}
