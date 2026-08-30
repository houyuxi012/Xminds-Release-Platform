//go:build darwin || linux

package breachcorpus

import (
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

type fileMetadata struct {
	mode os.FileMode
	size int64
	uid  uint32
	gid  uint32
	dev  uint64
	ino  uint64
}

func openDirectoryNoFollow(path string) (*os.File, error) {
	if !filepath.IsAbs(path) {
		return nil, ErrInvalidRelease
	}
	fd, err := unix.Open(string(filepath.Separator), unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_DIRECTORY, 0)
	if err != nil {
		return nil, ErrInvalidRelease
	}
	current := os.NewFile(uintptr(fd), string(filepath.Separator))
	if current == nil {
		_ = unix.Close(fd)
		return nil, ErrInvalidRelease
	}
	relative := strings.TrimPrefix(filepath.Clean(path), string(filepath.Separator))
	if relative == "" {
		return current, nil
	}
	for _, component := range strings.Split(relative, string(filepath.Separator)) {
		nextFD, err := unix.Openat(int(current.Fd()), component, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_DIRECTORY, 0)
		_ = current.Close()
		if err != nil {
			return nil, ErrInvalidRelease
		}
		current = os.NewFile(uintptr(nextFD), component)
		if current == nil {
			_ = unix.Close(nextFD)
			return nil, ErrInvalidRelease
		}
	}
	return current, nil
}

func openRegularFileAt(directory *os.File, name string) (*os.File, fileMetadata, error) {
	if directory == nil || name == "" || filepath.Base(name) != name {
		return nil, fileMetadata{}, ErrInvalidRelease
	}
	fd, err := unix.Openat(int(directory.Fd()), name, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, fileMetadata{}, ErrInvalidRelease
	}
	file := os.NewFile(uintptr(fd), name)
	if file == nil {
		_ = unix.Close(fd)
		return nil, fileMetadata{}, ErrInvalidRelease
	}
	metadata, err := metadataFor(file)
	if err != nil || !metadata.mode.IsRegular() {
		_ = file.Close()
		return nil, fileMetadata{}, ErrInvalidRelease
	}
	return file, metadata, nil
}

func metadataFor(file *os.File) (fileMetadata, error) {
	if file == nil {
		return fileMetadata{}, ErrInvalidRelease
	}
	info, err := file.Stat()
	if err != nil {
		return fileMetadata{}, ErrInvalidRelease
	}
	var stat unix.Stat_t
	if err := unix.Fstat(int(file.Fd()), &stat); err != nil {
		return fileMetadata{}, ErrInvalidRelease
	}
	return fileMetadata{
		mode: info.Mode(),
		size: info.Size(),
		uid:  stat.Uid,
		gid:  stat.Gid,
		dev:  uint64(stat.Dev),
		ino:  uint64(stat.Ino),
	}, nil
}

func sameOpenFile(left, right *os.File) bool {
	leftMetadata, leftErr := metadataFor(left)
	rightMetadata, rightErr := metadataFor(right)
	return leftErr == nil && rightErr == nil &&
		leftMetadata.dev == rightMetadata.dev && leftMetadata.ino == rightMetadata.ino
}
