//go:build !linux

package bpfmgr

import (
	"context"
	"fmt"
	"io"
	"runtime"
)

func RunOpenATAudit(ctx context.Context, opts OpenATAuditOptions, out io.Writer) error {
	return fmt.Errorf("%w: openat audit requires Linux, current platform is %s/%s", ErrUnsupported, runtime.GOOS, runtime.GOARCH)
}
