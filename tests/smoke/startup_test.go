package smoke_test

import (
	"errors"
	"os/exec"
	"strings"
	"testing"
)

func TestBinariesFailClosedBeforeConfigurationIsAvailable(t *testing.T) {
	t.Parallel()

	for _, testCase := range []struct {
		target string
		marker string
	}{
		{target: "../../apps/release-api", marker: "usage: release-api <serve|migrate>"},
		{target: "../../apps/release-worker", marker: "database URL is required"},
	} {
		testCase := testCase
		t.Run(testCase.target, func(t *testing.T) {
			t.Parallel()

			command := exec.Command("go", "run", testCase.target)
			output, err := command.CombinedOutput()

			var exitError *exec.ExitError
			if !errors.As(err, &exitError) {
				t.Fatalf("expected non-zero process exit, got err=%v output=%s", err, output)
			}
			if !strings.Contains(string(output), testCase.marker) {
				t.Fatalf("startup error missing from output: %s", output)
			}
		})
	}
}
