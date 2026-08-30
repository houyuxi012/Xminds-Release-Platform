package breachcorpus

import (
	"os"
	"path/filepath"
	"strings"
)

func ReadBuildRequestFile(path string) (BuildRequest, error) {
	if path == "" || strings.TrimSpace(path) != path || !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return BuildRequest{}, ErrInvalidRequest
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > maximumBuildRequestBytes {
		return BuildRequest{}, ErrInvalidRequest
	}
	file, err := os.Open(path)
	if err != nil {
		return BuildRequest{}, ErrInvalidRequest
	}
	defer file.Close()
	openedInfo, err := file.Stat()
	if err != nil || !os.SameFile(info, openedInfo) {
		return BuildRequest{}, ErrInvalidRequest
	}
	request, err := ReadBuildRequest(file)
	if err != nil {
		return BuildRequest{}, ErrInvalidRequest
	}
	afterInfo, err := file.Stat()
	if err != nil || !os.SameFile(info, afterInfo) || afterInfo.Size() != info.Size() {
		return BuildRequest{}, ErrInvalidRequest
	}
	return request, nil
}
