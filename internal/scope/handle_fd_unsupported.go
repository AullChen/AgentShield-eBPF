//go:build !linux

package scope

func (*Handle) DuplicateFD() (int, error) {
	return -1, ErrHandleUnavailable
}
