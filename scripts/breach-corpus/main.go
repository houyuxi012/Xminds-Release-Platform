// Command breach-corpus builds and verifies governed breached-password digest releases.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"xminds-release-platform/internal/breachcorpus"
	"xminds-release-platform/internal/platform/buildinfo"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr, time.Now))
}

func run(arguments []string, stdout, stderr io.Writer, clock func() time.Time) int {
	if stdout == nil || stderr == nil || clock == nil || len(arguments) == 0 {
		writeCLIError(stderr, "参数无效")
		return 2
	}
	switch arguments[0] {
	case "build":
		return runBuild(arguments[1:], stdout, stderr, clock)
	case "verify":
		return runVerify(arguments[1:], stdout, stderr)
	default:
		writeCLIError(stderr, "参数无效")
		return 2
	}
}

func runBuild(arguments []string, stdout, stderr io.Writer, clock func() time.Time) int {
	flags := flag.NewFlagSet("breach-corpus build", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	requestPath := flags.String("request", "", "")
	outputRoot := flags.String("output-root", "", "")
	var inputs inputFlags
	flags.Var(&inputs, "input", "")
	if err := flags.Parse(arguments); err != nil || flags.NArg() != 0 ||
		!cleanAbsolutePath(*requestPath) || !cleanAbsolutePath(*outputRoot) || len(inputs) == 0 {
		writeCLIError(stderr, "参数无效")
		return 2
	}
	request, err := breachcorpus.ReadBuildRequestFile(*requestPath)
	if err != nil {
		writeCLIError(stderr, "构建请求无效")
		return 1
	}
	if err := breachcorpus.ValidateInputs(request, []breachcorpus.Input(inputs)); err != nil {
		writeCLIError(stderr, "参数无效")
		return 2
	}
	info := buildinfo.Current()
	result, err := breachcorpus.Build(
		context.Background(),
		request,
		[]breachcorpus.Input(inputs),
		*outputRoot,
		breachcorpus.Generator{Name: "xminds-breach-corpus", Version: info.Version, Commit: info.Commit},
		clock,
	)
	if err != nil {
		writeCLIError(stderr, "语料构建失败")
		return 1
	}
	if err := encodeResult(stdout, result); err != nil {
		writeCLIError(stderr, "结果输出失败")
		return 1
	}
	return 0
}

func runVerify(arguments []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("breach-corpus verify", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	mode := flags.String("mode", string(breachcorpus.ArtifactMode), "")
	releaseDirectory := flags.String("release-dir", "", "")
	ownerUID := flags.String("expected-owner-uid", "", "")
	groupGID := flags.String("expected-group-gid", "", "")
	if err := flags.Parse(arguments); err != nil || flags.NArg() != 0 || !cleanAbsolutePath(*releaseDirectory) {
		writeCLIError(stderr, "参数无效")
		return 2
	}

	options := breachcorpus.VerifyOptions{}
	switch breachcorpus.VerificationMode(*mode) {
	case breachcorpus.ArtifactMode:
		if *ownerUID != "" || *groupGID != "" {
			writeCLIError(stderr, "参数无效")
			return 2
		}
		options.Mode = breachcorpus.ArtifactMode
	case breachcorpus.DeploymentMode:
		uid, uidErr := parseUint32(*ownerUID)
		gid, gidErr := parseUint32(*groupGID)
		if uidErr != nil || gidErr != nil {
			writeCLIError(stderr, "参数无效")
			return 2
		}
		options.Mode = breachcorpus.DeploymentMode
		options.ExpectedOwnership = &breachcorpus.OwnershipExpectation{OwnerUID: uid, GroupGID: gid}
	default:
		writeCLIError(stderr, "参数无效")
		return 2
	}

	release, err := breachcorpus.VerifyRelease(*releaseDirectory, options)
	if err != nil {
		writeCLIError(stderr, "语料验证失败")
		return 1
	}
	if err := encodeResult(stdout, release.Result); err != nil {
		writeCLIError(stderr, "结果输出失败")
		return 1
	}
	return 0
}

type inputFlags []breachcorpus.Input

func (values *inputFlags) String() string { return "" }

func (values *inputFlags) Set(raw string) error {
	sourceID, path, found := strings.Cut(raw, "=")
	if !found || sourceID == "" || !cleanAbsolutePath(path) {
		return errors.New("invalid input binding")
	}
	*values = append(*values, breachcorpus.Input{SourceID: sourceID, Path: path})
	return nil
}

func cleanAbsolutePath(path string) bool {
	return path != "" && strings.TrimSpace(path) == path && filepath.IsAbs(path) && filepath.Clean(path) == path
}

func parseUint32(raw string) (uint32, error) {
	if raw == "" {
		return 0, errors.New("missing numeric identifier")
	}
	value, err := strconv.ParseUint(raw, 10, 32)
	if err != nil || value > math.MaxUint32 {
		return 0, errors.New("invalid numeric identifier")
	}
	return uint32(value), nil
}

func encodeResult(writer io.Writer, result breachcorpus.Result) error {
	encoder := json.NewEncoder(writer)
	encoder.SetEscapeHTML(false)
	return encoder.Encode(result)
}

func writeCLIError(writer io.Writer, message string) {
	if writer != nil {
		_, _ = fmt.Fprintln(writer, message)
	}
}
