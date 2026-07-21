//go:build linux

package scope

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

const defaultCgroupRoot = "/sys/fs/cgroup"

type LinuxResolver struct {
	root string
}

func NewLinuxResolver(root string) (*LinuxResolver, error) {
	if root == "" {
		root = defaultCgroupRoot
	}
	resolvedRoot, err := filepath.EvalSymlinks(root)
	if err != nil {
		return nil, fmt.Errorf("resolve cgroup root: %w", err)
	}
	var statfs unix.Statfs_t
	if err := unix.Statfs(resolvedRoot, &statfs); err != nil {
		return nil, fmt.Errorf("stat cgroup root filesystem: %w", err)
	}
	if statfs.Type != unix.CGROUP2_SUPER_MAGIC {
		return nil, fmt.Errorf("%q is not a cgroup v2 filesystem", resolvedRoot)
	}
	return &LinuxResolver{root: filepath.Clean(resolvedRoot)}, nil
}

func (resolver *LinuxResolver) ResolvePath(path string) (*Handle, error) {
	if path == "" {
		return nil, ErrInvalidTarget
	}
	if !filepath.IsAbs(path) {
		path = filepath.Join(resolver.root, path)
	}
	clean := filepath.Clean(path)
	resolved, err := filepath.EvalSymlinks(clean)
	if err != nil {
		return nil, fmt.Errorf("resolve cgroup path: %w", err)
	}
	if resolved != clean {
		return nil, errors.New("cgroup path must not contain symbolic links")
	}
	relative, err := filepath.Rel(resolver.root, resolved)
	if err != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return nil, fmt.Errorf("cgroup path %q escapes trusted root %q", resolved, resolver.root)
	}

	entries, err := os.ReadDir(resolved)
	if err != nil {
		return nil, fmt.Errorf("read cgroup directory: %w", err)
	}
	for _, entry := range entries {
		if entry.IsDir() {
			return nil, fmt.Errorf("cgroup %q is not an exact leaf: child %q exists", resolved, entry.Name())
		}
	}

	fd, err := unix.Open(resolved, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, fmt.Errorf("open cgroup directory: %w", err)
	}
	file := os.NewFile(uintptr(fd), resolved)
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("stat opened cgroup directory: %w", err)
	}
	if stat.Ino == 0 {
		_ = file.Close()
		return nil, errors.New("opened cgroup has zero inode identity")
	}
	return &Handle{ID: stat.Ino, Path: resolved, closer: file}, nil
}

func (resolver *LinuxResolver) ResolvePID(pid int) (*Handle, error) {
	if pid < 1 {
		return nil, ErrInvalidTarget
	}
	selfNamespace, err := os.Stat("/proc/self/ns/cgroup")
	if err != nil {
		return nil, fmt.Errorf("stat current cgroup namespace: %w", err)
	}
	targetNamespace, err := os.Stat(filepath.Join("/proc", strconv.Itoa(pid), "ns/cgroup"))
	if err != nil {
		return nil, fmt.Errorf("stat target cgroup namespace: %w", err)
	}
	if !os.SameFile(selfNamespace, targetNamespace) {
		return nil, errors.New("target PID is in a different cgroup namespace")
	}

	file, err := os.Open(filepath.Join("/proc", strconv.Itoa(pid), "cgroup"))
	if err != nil {
		return nil, fmt.Errorf("open target cgroup membership: %w", err)
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		hierarchy, path, ok := strings.Cut(scanner.Text(), "::")
		if ok && hierarchy == "0" {
			return resolver.ResolvePath(filepath.Join(resolver.root, strings.TrimPrefix(path, "/")))
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read target cgroup membership: %w", err)
	}
	return nil, errors.New("target PID has no unified cgroup v2 membership")
}
