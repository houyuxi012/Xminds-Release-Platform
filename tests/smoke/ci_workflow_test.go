package smoke_test

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
)

func TestCIWorkflowPreservesRequiredQualityGates(t *testing.T) {
	t.Parallel()

	workflowPath := filepath.Join("..", "..", ".github", "workflows", "ci.yml")
	content, err := os.ReadFile(workflowPath)
	if err != nil {
		t.Fatalf("read CI workflow: %v", err)
	}

	var document map[string]any
	if err := yaml.Unmarshal(content, &document); err != nil {
		t.Fatalf("parse CI workflow as YAML: %v", err)
	}

	workflow := string(content)
	for _, required := range []string{
		"pull_request:",
		"push:",
		"contents: read",
		"cancel-in-progress: true",
		"runs-on: ubuntu-24.04",
		"timeout-minutes: 30",
		"persist-credentials: false",
		"quality:",
		"integration:",
		"console-e2e:",
		"make verify",
		"make test-integration",
		"make console-e2e",
		"docker compose -f compose.integration.yaml up -d --wait postgres minio",
		"docker compose -f compose.integration.yaml down -v --remove-orphans",
		"node-version-file: .node-version",
		"go-version-file: go.mod",
	} {
		if !strings.Contains(workflow, required) {
			t.Errorf("CI workflow is missing required contract %q", required)
		}
	}

	for _, forbidden := range []string{
		"pull_request_target:",
		"contents: write",
		"${{ secrets.",
		"@main",
		"@master",
	} {
		if strings.Contains(workflow, forbidden) {
			t.Errorf("CI workflow contains forbidden contract %q", forbidden)
		}
	}

	usesPattern := regexp.MustCompile(`(?m)^\s*uses:\s*([^#\s]+)`)
	actionPattern := regexp.MustCompile(`^actions/(checkout|setup-go|setup-node)@[0-9a-f]{40}$`)
	uses := usesPattern.FindAllStringSubmatch(workflow, -1)
	if len(uses) == 0 {
		t.Fatal("CI workflow does not reference any actions")
	}
	for _, match := range uses {
		if !actionPattern.MatchString(match[1]) {
			t.Errorf("CI action must be approved and pinned to a full commit SHA: %s", match[1])
		}
	}
	if installs := strings.Count(
		workflow,
		"./node_modules/.bin/playwright install --with-deps chromium",
	); installs != 2 {
		t.Errorf("Quality and Console E2E jobs must each install Chromium, got %d install steps", installs)
	}

	composeContent, err := os.ReadFile(filepath.Join("..", "..", "compose.integration.yaml"))
	if err != nil {
		t.Fatalf("read integration compose file: %v", err)
	}
	compose := string(composeContent)
	for _, requiredImage := range []string{
		"image: postgres:18-alpine",
		"image: minio/minio:RELEASE.2025-09-07T16-13-09Z",
	} {
		if !strings.Contains(compose, requiredImage) {
			t.Errorf("integration compose file is missing required image %q", requiredImage)
		}
	}

	nodeVersion, err := os.ReadFile(filepath.Join("..", "..", ".node-version"))
	if err != nil {
		t.Fatalf("read Node.js version contract: %v", err)
	}
	if strings.TrimSpace(string(nodeVersion)) != "24.20.0" {
		t.Errorf("Node.js version contract must be 24.20.0, got %q", strings.TrimSpace(string(nodeVersion)))
	}

	goModule, err := os.ReadFile(filepath.Join("..", "..", "go.mod"))
	if err != nil {
		t.Fatalf("read Go version contract: %v", err)
	}
	if !strings.Contains(string(goModule), "toolchain go1.26.5") {
		t.Error("Go version contract must preserve toolchain go1.26.5")
	}

	dependabotContent, err := os.ReadFile(filepath.Join("..", "..", ".github", "dependabot.yml"))
	if err != nil {
		t.Fatalf("read Dependabot configuration: %v", err)
	}
	var dependabotDocument map[string]any
	if err := yaml.Unmarshal(dependabotContent, &dependabotDocument); err != nil {
		t.Fatalf("parse Dependabot configuration as YAML: %v", err)
	}
	dependabot := string(dependabotContent)
	for _, required := range []string{
		"package-ecosystem: github-actions",
		"interval: weekly",
		"timezone: Asia/Shanghai",
		"open-pull-requests-limit: 5",
	} {
		if !strings.Contains(dependabot, required) {
			t.Errorf("Dependabot configuration is missing required contract %q", required)
		}
	}
}
