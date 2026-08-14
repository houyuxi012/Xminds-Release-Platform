package smoke_test

import (
	"errors"
	"os/exec"
	"strings"
	"testing"
)

func TestBinariesFailClosedBeforeConfigurationIsAvailable(t *testing.T) {
	t.Parallel()

	for _, target := range []string{
		"../../apps/release-api",
		"../../apps/release-worker",
	} {
		target := target
		t.Run(target, func(t *testing.T) {
			t.Parallel()

			command := exec.Command("go", "run", target)
			output, err := command.CombinedOutput()

			var exitError *exec.ExitError
			if !errors.As(err, &exitError) {
				t.Fatalf("expected non-zero process exit, got err=%v output=%s", err, output)
			}
			if !strings.Contains(string(output), "configuration is not initialized") {
				t.Fatalf("startup error missing from output: %s", output)
			}
		})
	}
}
