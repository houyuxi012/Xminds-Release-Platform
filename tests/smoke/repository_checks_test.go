package smoke_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestMacOSMetadataCheckRejectsPollution(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	writeFixture(t, filepath.Join(root, "src", "clean.txt"), "clean")
	runScriptExpectSuccess(t, "../../scripts/check-macos-metadata.sh", root)

	writeFixture(t, filepath.Join(root, "src", ".DS_Store"), "pollution")
	runScriptExpectFailure(t, "../../scripts/check-macos-metadata.sh", root)
}

func TestBoundaryCheckRejectsEscapingRelativeImports(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	writeFixture(
		t,
		filepath.Join(root, "internal", "safe.go"),
		"package internal\n\nimport \"xminds-release-platform/internal/platform/buildinfo\"\n\nfunc fixtureText() string { return \"import config from '../../../parent/config';\" }\n",
	)
	runScriptExpectSuccess(t, "../../scripts/check-boundaries.sh", root)

	writeFixture(t, filepath.Join(root, "internal", "unsafe.ts"), "import config from '../../../parent/config';\nvoid config;\n")
	runScriptExpectFailure(t, "../../scripts/check-boundaries.sh", root)
}

func writeFixture(t *testing.T, path string, content string) {
	t.Helper()

	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("create fixture directory: %v", err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
}

func runScriptExpectSuccess(t *testing.T, script string, root string) {
	t.Helper()

	command := exec.Command(script, root)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("expected success: err=%v output=%s", err, output)
	}
}

func runScriptExpectFailure(t *testing.T, script string, root string) {
	t.Helper()

	command := exec.Command(script, root)
	if output, err := command.CombinedOutput(); err == nil {
		t.Fatalf("expected failure: output=%s", output)
	}
}
