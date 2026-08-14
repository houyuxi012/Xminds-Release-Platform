package main

import (
	"fmt"
	"os"

	"xminds-release-platform/internal/platform/buildinfo"
)

func main() {
	info := buildinfo.Current()
	fmt.Fprintf(
		os.Stderr,
		"%s release-worker: configuration is not initialized (version=%s commit=%s)\n",
		info.Product,
		info.Version,
		info.Commit,
	)
	os.Exit(1)
}
