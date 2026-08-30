package endpoint

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

const maximumCABundleBytes = 1024 * 1024

var (
	ErrCABundleDirectoryInvalid = errors.New("distribution endpoint CA bundle directory is invalid")
	ErrCABundleReferenceInvalid = errors.New("distribution endpoint CA bundle reference is invalid")
	ErrCABundleInvalid          = errors.New("distribution endpoint CA bundle is invalid")
)

var caBundleReferencePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)

type DirectoryCABundleLoader struct {
	directory string
}

func NewDirectoryCABundleLoader(directory string) (*DirectoryCABundleLoader, error) {
	directory = filepath.Clean(strings.TrimSpace(directory))
	if !filepath.IsAbs(directory) {
		return nil, ErrCABundleDirectoryInvalid
	}
	information, err := os.Stat(directory)
	if err != nil || !information.IsDir() {
		return nil, errors.Join(ErrCABundleDirectoryInvalid, err)
	}
	return &DirectoryCABundleLoader{directory: directory}, nil
}

func (loader *DirectoryCABundleLoader) Load(ctx context.Context, reference string) ([]byte, error) {
	if loader == nil || !filepath.IsAbs(loader.directory) {
		return nil, ErrCABundleDirectoryInvalid
	}
	reference = strings.TrimSpace(reference)
	if !caBundleReferencePattern.MatchString(reference) {
		return nil, ErrCABundleReferenceInvalid
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	file, err := os.OpenInRoot(loader.directory, reference)
	if err != nil {
		return nil, errors.Join(ErrCABundleInvalid, err)
	}
	defer file.Close()
	information, err := file.Stat()
	if err != nil || !information.Mode().IsRegular() || information.Size() <= 0 || information.Size() > maximumCABundleBytes {
		return nil, errors.Join(ErrCABundleInvalid, err)
	}
	bundle, err := io.ReadAll(io.LimitReader(file, maximumCABundleBytes+1))
	if err != nil || len(bundle) == 0 || len(bundle) > maximumCABundleBytes {
		return nil, errors.Join(ErrCABundleInvalid, err)
	}
	return bundle, nil
}
