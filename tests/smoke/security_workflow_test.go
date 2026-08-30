package smoke_test

import (
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
)

type securityWorkflow struct {
	Name        string                 `yaml:"name"`
	Triggers    map[string]any         `yaml:"on"`
	Permissions map[string]string      `yaml:"permissions"`
	Concurrency workflowConcurrency    `yaml:"concurrency"`
	Jobs        map[string]securityJob `yaml:"jobs"`
}

type workflowConcurrency struct {
	Group            string `yaml:"group"`
	CancelInProgress bool   `yaml:"cancel-in-progress"`
}

type securityJob struct {
	Name           string           `yaml:"name"`
	RunsOn         string           `yaml:"runs-on"`
	TimeoutMinutes int              `yaml:"timeout-minutes"`
	Strategy       workflowStrategy `yaml:"strategy"`
	Steps          []securityStep   `yaml:"steps"`
}

type workflowStrategy struct {
	FailFast bool           `yaml:"fail-fast"`
	Matrix   workflowMatrix `yaml:"matrix"`
}

type workflowMatrix struct {
	Language []string              `yaml:"language"`
	Include  []workflowMatrixEntry `yaml:"include"`
}

type workflowMatrixEntry struct {
	Language  string `yaml:"language"`
	BuildMode string `yaml:"build-mode"`
}

type securityStep struct {
	Name string         `yaml:"name"`
	Uses string         `yaml:"uses"`
	With map[string]any `yaml:"with"`
}

func TestCodeQLWorkflowEnforcesStaticAnalysisGate(t *testing.T) {
	t.Parallel()

	workflow, raw := readSecurityWorkflow(t, "codeql.yml")
	if workflow.Name != "CodeQL" {
		t.Fatalf("CodeQL workflow name = %q, want CodeQL", workflow.Name)
	}
	assertTriggers(t, workflow.Triggers, "pull_request", "push", "schedule")
	assertPermissions(t, workflow.Permissions, map[string]string{
		"contents":        "read",
		"packages":        "read",
		"security-events": "write",
	})
	if !workflow.Concurrency.CancelInProgress || workflow.Concurrency.Group == "" {
		t.Fatal("CodeQL workflow must cancel superseded runs in a named concurrency group")
	}

	job, ok := workflow.Jobs["analyze"]
	if !ok {
		t.Fatal("CodeQL workflow is missing analyze job")
	}
	if job.Name != "CodeQL (${{ matrix.language }})" {
		t.Fatalf("CodeQL job name = %q", job.Name)
	}
	if job.RunsOn != "ubuntu-24.04" || job.TimeoutMinutes != 30 {
		t.Fatalf("CodeQL execution boundary = %s/%d minutes", job.RunsOn, job.TimeoutMinutes)
	}
	wantMatrix := []workflowMatrixEntry{
		{Language: "go", BuildMode: "autobuild"},
		{Language: "javascript-typescript", BuildMode: "none"},
	}
	if got := job.Strategy.Matrix.Include; !reflect.DeepEqual(got, wantMatrix) {
		t.Fatalf("CodeQL language/build matrix = %v, want %v", got, wantMatrix)
	}
	if len(job.Strategy.Matrix.Language) != 0 {
		t.Fatalf("CodeQL matrix must define build mode per language, got shared language list %v", job.Strategy.Matrix.Language)
	}
	if job.Strategy.FailFast {
		t.Fatal("CodeQL matrix must preserve findings from both languages when one job fails")
	}

	checkout := requireActionStep(t, job.Steps, `^actions/checkout@[0-9a-f]{40}$`)
	if got := fmt.Sprint(checkout.With["persist-credentials"]); got != "false" {
		t.Fatalf("CodeQL checkout persist-credentials = %q, want false", got)
	}
	init := requireActionStep(t, job.Steps, `^github/codeql-action/init@[0-9a-f]{40}$`)
	if got := fmt.Sprint(init.With["languages"]); got != "${{ matrix.language }}" {
		t.Fatalf("CodeQL init languages = %q", got)
	}
	if got := fmt.Sprint(init.With["build-mode"]); got != "${{ matrix.build-mode }}" {
		t.Fatalf("CodeQL build mode = %q, want matrix-specific mode", got)
	}
	if got := fmt.Sprint(init.With["queries"]); got != "security-extended" {
		t.Fatalf("CodeQL query suite = %q, want security-extended", got)
	}
	analysis := requireActionStep(t, job.Steps, `^github/codeql-action/analyze@[0-9a-f]{40}$`)
	if got := fmt.Sprint(analysis.With["category"]); got != "/language:${{ matrix.language }}" {
		t.Fatalf("CodeQL result category = %q", got)
	}
	assertWorkflowHasNoUnsafeContracts(t, raw)
}

func TestDependencyReviewWorkflowRejectsHighRiskDependencyChanges(t *testing.T) {
	t.Parallel()

	workflow, raw := readSecurityWorkflow(t, "dependency-review.yml")
	if workflow.Name != "Dependency Review" {
		t.Fatalf("dependency review workflow name = %q", workflow.Name)
	}
	assertTriggers(t, workflow.Triggers, "pull_request")
	assertPermissions(t, workflow.Permissions, map[string]string{"contents": "read"})
	if !workflow.Concurrency.CancelInProgress || workflow.Concurrency.Group == "" {
		t.Fatal("dependency review must cancel superseded runs in a named concurrency group")
	}

	job, ok := workflow.Jobs["review"]
	if !ok {
		t.Fatal("dependency review workflow is missing review job")
	}
	if job.Name != "Dependency Review" {
		t.Fatalf("dependency review job name = %q", job.Name)
	}
	if job.RunsOn != "ubuntu-24.04" || job.TimeoutMinutes != 10 {
		t.Fatalf("dependency review execution boundary = %s/%d minutes", job.RunsOn, job.TimeoutMinutes)
	}
	review := requireActionStep(t, job.Steps, `^actions/dependency-review-action@[0-9a-f]{40}$`)
	wantInputs := map[string]string{
		"fail-on-severity":                   "high",
		"fail-on-scopes":                     "runtime, development",
		"vulnerability-check":                "true",
		"license-check":                      "true",
		"comment-summary-in-pr":              "never",
		"retry-on-snapshot-warnings":         "true",
		"retry-on-snapshot-warnings-timeout": "120",
	}
	for key, want := range wantInputs {
		if got := fmt.Sprint(review.With[key]); got != want {
			t.Errorf("dependency review input %s = %q, want %q", key, got, want)
		}
	}
	assertWorkflowHasNoUnsafeContracts(t, raw)
}

func readSecurityWorkflow(t *testing.T, name string) (securityWorkflow, string) {
	t.Helper()

	path := filepath.Join("..", "..", ".github", "workflows", name)
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", name, err)
	}
	var workflow securityWorkflow
	if err := yaml.Unmarshal(content, &workflow); err != nil {
		t.Fatalf("parse %s as YAML: %v", name, err)
	}
	return workflow, string(content)
}

func assertTriggers(t *testing.T, got map[string]any, want ...string) {
	t.Helper()

	if len(got) != len(want) {
		t.Fatalf("workflow triggers = %v, want exactly %v", triggerNames(got), want)
	}
	for _, trigger := range want {
		if _, ok := got[trigger]; !ok {
			t.Errorf("workflow is missing %s trigger", trigger)
		}
	}
}

func triggerNames(triggers map[string]any) []string {
	names := make([]string, 0, len(triggers))
	for name := range triggers {
		names = append(names, name)
	}
	return names
}

func assertPermissions(t *testing.T, got, want map[string]string) {
	t.Helper()

	if !reflect.DeepEqual(got, want) {
		t.Fatalf("workflow permissions = %v, want exact least-privilege set %v", got, want)
	}
}

func requireActionStep(t *testing.T, steps []securityStep, pattern string) securityStep {
	t.Helper()

	matcher := regexp.MustCompile(pattern)
	for _, step := range steps {
		if matcher.MatchString(step.Uses) {
			return step
		}
	}
	t.Fatalf("workflow is missing action matching %s", pattern)
	return securityStep{}
}

func assertWorkflowHasNoUnsafeContracts(t *testing.T, workflow string) {
	t.Helper()

	for _, forbidden := range []string{
		"pull_request_target:",
		"contents: write",
		"pull-requests: write",
		"${{ secrets.",
		"@main",
		"@master",
	} {
		if strings.Contains(workflow, forbidden) {
			t.Errorf("security workflow contains forbidden contract %q", forbidden)
		}
	}
}
