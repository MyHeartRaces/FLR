package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// Re-enter the real CLI in a child: fail uses os.Exit and must not terminate
// the test runner. No test seam is added to the production command.
func TestRetiredEnableHomeCLIChild(t *testing.T) {
	if os.Getenv("FLR_RETIRED_HOME_TEST_CHILD") != "1" {
		return
	}
	for i, arg := range os.Args {
		if arg == "--" {
			os.Args = append([]string{os.Args[0]}, os.Args[i+1:]...)
			main()
			return
		}
	}
	t.Fatal("CLI helper arguments missing")
}

// Restoring the old read/modify/write branch must fail this test. Rejection
// must happen before policy loading, settings recovery or native side effects,
// and must tell the operator which supported activation path to use.
func TestEnableHomeRejectedBeforePolicyOrStateAccess(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "policy-must-not-be-read")
	cases := [][]string{
		{"enable-home", "--policy", missing},
		{"enable-home", "--policy", missing, "--backup", filepath.Join(t.TempDir(), "backup-must-not-be-created")},
		{"enable-home", "--unknown-legacy-flag"},
	}
	for _, args := range cases {
		cmd := exec.Command(os.Args[0], append([]string{"-test.run=^TestRetiredEnableHomeCLIChild$", "--"}, args...)...)
		cmd.Env = append(os.Environ(), "FLR_RETIRED_HOME_TEST_CHILD=1")
		output, err := cmd.CombinedOutput()
		exit, ok := err.(*exec.ExitError)
		if !ok || exit.ExitCode() != 1 {
			t.Fatalf("retired command did not reject safely: %v %s", err, output)
		}
		text := string(output)
		if !strings.Contains(text, "enable-home is retired") || !strings.Contains(text, "Proxy management") {
			t.Fatalf("legacy command entered policy/state parsing instead of early retirement: %s", text)
		}
		if _, err := os.Stat(missing); !os.IsNotExist(err) {
			t.Fatal("retired command changed policy path", err)
		}
	}
}
