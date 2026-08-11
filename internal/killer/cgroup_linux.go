//go:build linux

package killer

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/agentshield/agentshield-ebpf/internal/scope"
	"golang.org/x/sys/unix"
)

const defaultCgroupRoot = "/sys/fs/cgroup"

type linuxCgroupBackend struct {
	root string
}

type linuxCgroupHandle struct {
	fd       int
	identity CgroupIdentity
}

func NewLinuxBackend(root string) (CgroupBackend, error) {
	if root == "" {
		root = defaultCgroupRoot
	}
	resolved, err := filepath.EvalSymlinks(root)
	if err != nil {
		return nil, fmt.Errorf("resolve cgroup root: %w", err)
	}
	var statfs unix.Statfs_t
	if err := unix.Statfs(resolved, &statfs); err != nil {
		return nil, fmt.Errorf("stat cgroup root: %w", err)
	}
	if statfs.Type != unix.CGROUP2_SUPER_MAGIC {
		return nil, fmt.Errorf("%w: %q is not a cgroup v2 filesystem", ErrUnsupported, resolved)
	}
	return &linuxCgroupBackend{root: filepath.Clean(resolved)}, nil
}

func (backend *linuxCgroupBackend) CurrentCoreCgroup(ctx context.Context) (CgroupIdentity, error) {
	if err := ctx.Err(); err != nil {
		return CgroupIdentity{}, err
	}
	relative, err := readUnifiedCgroupPath(os.Getpid())
	if err != nil {
		return CgroupIdentity{}, fmt.Errorf("read Core cgroup membership: %w", err)
	}
	target := filepath.Join(backend.root, strings.TrimPrefix(relative, "/"))
	handle, err := backend.openCgroupPath(ctx, target)
	if err != nil {
		return CgroupIdentity{}, err
	}
	defer handle.Close()
	return handle.Identity(), nil
}

func (backend *linuxCgroupBackend) OpenCgroup(
	ctx context.Context,
	trusted *scope.Handle,
) (CgroupHandle, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if trusted == nil || trusted.ID == 0 || !filepath.IsAbs(trusted.Path) {
		return nil, fmt.Errorf("%w: active scope has no complete trusted handle", ErrCgroupIdentityMismatch)
	}

	duplicate, err := trusted.DuplicateFD()
	if err != nil {
		return nil, fmt.Errorf("duplicate active cgroup handle: %w", err)
	}
	actualPath, err := os.Readlink(filepath.Join("/proc/self/fd", strconv.Itoa(duplicate)))
	if err != nil {
		_ = unix.Close(duplicate)
		return nil, fmt.Errorf("resolve active cgroup descriptor: %w", err)
	}
	actualPath = filepath.Clean(actualPath)
	expectedPath := filepath.Clean(trusted.Path)
	if actualPath != expectedPath {
		_ = unix.Close(duplicate)
		return nil, fmt.Errorf("%w: descriptor path=%q active path=%q",
			ErrCgroupIdentityMismatch, actualPath, expectedPath)
	}
	relative, err := filepath.Rel(backend.root, actualPath)
	if err != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		_ = unix.Close(duplicate)
		return nil, fmt.Errorf("%w: cgroup path %q escapes trusted root %q",
			ErrCgroupIdentityMismatch, actualPath, backend.root)
	}
	return newLinuxCgroupHandle(
		ctx,
		duplicate,
		CgroupIdentity{ID: trusted.ID, Path: actualPath},
		true,
	)
}

func (backend *linuxCgroupBackend) openCgroupPath(
	ctx context.Context,
	target string,
) (*linuxCgroupHandle, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if !filepath.IsAbs(target) {
		target = filepath.Join(backend.root, target)
	}
	clean := filepath.Clean(target)
	resolved, err := filepath.EvalSymlinks(clean)
	if err != nil {
		return nil, fmt.Errorf("resolve cgroup path: %w", err)
	}
	if resolved != clean {
		return nil, errors.New("cgroup path must not contain symbolic links")
	}
	relative, err := filepath.Rel(backend.root, resolved)
	if err != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return nil, fmt.Errorf("cgroup path %q escapes trusted root %q", resolved, backend.root)
	}

	fd, err := unix.Open(resolved, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, fmt.Errorf("open cgroup directory: %w", err)
	}
	return newLinuxCgroupHandle(
		ctx,
		fd,
		CgroupIdentity{Path: filepath.Clean(resolved)},
		false,
	)
}

func newLinuxCgroupHandle(
	ctx context.Context,
	fd int,
	expected CgroupIdentity,
	requireLeaf bool,
) (*linuxCgroupHandle, error) {
	closeOnError := true
	defer func() {
		if closeOnError {
			_ = unix.Close(fd)
		}
	}()
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		return nil, fmt.Errorf("stat opened cgroup: %w", err)
	}
	if stat.Ino == 0 {
		return nil, errors.New("opened cgroup has zero inode identity")
	}
	var statfs unix.Statfs_t
	if err := unix.Fstatfs(fd, &statfs); err != nil {
		return nil, fmt.Errorf("stat opened cgroup filesystem: %w", err)
	}
	if statfs.Type != unix.CGROUP2_SUPER_MAGIC {
		return nil, fmt.Errorf("%w: active descriptor is not on cgroup v2", ErrUnsupported)
	}
	if expected.ID != 0 && stat.Ino != expected.ID {
		return nil, fmt.Errorf("%w: descriptor=%d active=%d",
			ErrCgroupIdentityMismatch, stat.Ino, expected.ID)
	}
	if requireLeaf {
		if err := requireLeafCgroup(fd); err != nil {
			return nil, err
		}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	closeOnError = false
	return &linuxCgroupHandle{
		fd: fd,
		identity: CgroupIdentity{
			ID:   stat.Ino,
			Path: filepath.Clean(expected.Path),
		},
	}, nil
}

func requireLeafCgroup(fd int) error {
	iterator, err := unix.Openat(
		fd,
		".",
		unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW,
		0,
	)
	if err != nil {
		return fmt.Errorf("open cgroup directory iterator: %w", err)
	}
	directory := os.NewFile(uintptr(iterator), "cgroup-leaf-check")
	if directory == nil {
		_ = unix.Close(iterator)
		return errors.New("wrap cgroup directory descriptor")
	}
	defer directory.Close()
	entries, err := directory.ReadDir(-1)
	if err != nil {
		return fmt.Errorf("inspect cgroup children: %w", err)
	}
	for _, entry := range entries {
		var stat unix.Stat_t
		if err := unix.Fstatat(fd, entry.Name(), &stat, unix.AT_SYMLINK_NOFOLLOW); err != nil {
			return fmt.Errorf("inspect cgroup entry %q: %w", entry.Name(), err)
		}
		if stat.Mode&unix.S_IFMT == unix.S_IFDIR {
			return fmt.Errorf("%w: child %q exists", ErrCgroupNotLeaf, entry.Name())
		}
	}
	return nil
}

func readUnifiedCgroupPath(pid int) (string, error) {
	file, err := os.Open(filepath.Join("/proc", strconv.Itoa(pid), "cgroup"))
	if err != nil {
		return "", err
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		hierarchy, memberPath, ok := strings.Cut(scanner.Text(), "::")
		if ok && hierarchy == "0" && memberPath != "" {
			return memberPath, nil
		}
	}
	if err := scanner.Err(); err != nil {
		return "", err
	}
	return "", errors.New("process has no unified cgroup v2 membership")
}

func (handle *linuxCgroupHandle) Identity() CgroupIdentity {
	return handle.identity
}

func (handle *linuxCgroupHandle) Kill(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if handle.fd < 0 {
		return errors.New("cgroup handle is closed")
	}
	if err := requireLeafCgroup(handle.fd); err != nil {
		return err
	}
	control, err := unix.Openat(
		handle.fd,
		"cgroup.kill",
		unix.O_WRONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW,
		0,
	)
	if err != nil {
		if errors.Is(err, unix.ENOENT) || errors.Is(err, unix.EOPNOTSUPP) {
			return fmt.Errorf("%w: cgroup.kill is unavailable: %v", ErrUnsupported, err)
		}
		return err
	}
	defer unix.Close(control)
	for {
		written, err := unix.Write(control, []byte("1"))
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if err != nil {
			return err
		}
		if written != 1 {
			return io.ErrShortWrite
		}
		return nil
	}
}

func (handle *linuxCgroupHandle) Close() error {
	if handle.fd < 0 {
		return nil
	}
	err := unix.Close(handle.fd)
	handle.fd = -1
	return err
}
