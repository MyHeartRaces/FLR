package native

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// Only the test executable runs; no router tools or persistent children.
func TestCommandPipeHelper(t *testing.T) {
	mode := os.Getenv("FLR_PIPE_HELPER")
	if mode == "" {
		return
	}
	switch mode {
	case "echo":
		if _, e := io.Copy(os.Stdout, os.Stdin); e != nil {
			os.Exit(3)
		}
		fmt.Fprint(os.Stderr, "ordinary exit")
		os.Exit(1)
	case "closed-input":
		_ = os.Stdin.Close()
		fmt.Fprint(os.Stdout, "input declined")
	case "stdin-parent":
		child := exec.Command(os.Args[0], "-test.run=^TestCommandPipeHelper$")
		child.Env = append(os.Environ(), "FLR_PIPE_HELPER=sleep")
		child.Stdin = os.Stdin
		if e := child.Start(); e != nil {
			os.Exit(3)
		}
		os.Exit(1)
	case "sleep":
		time.Sleep(4 * time.Second)
	default:
		os.Exit(3)
	}
	os.Exit(0)
}

// Closing output pipes when the process exits would lose buffered output;
// converting every nonzero status to an interruption would lose exit semantics.
func TestExecuteDrainsPipesBeforeReturningExit(t *testing.T) {
	t.Setenv("FLR_PIPE_HELPER", "echo")
	input := strings.Repeat("a", 48<<10)
	r := Execute(context.Background(), 2*time.Second, input, os.Args[0], "-test.run=^TestCommandPipeHelper$")
	if string(r.Stdout) != input || r.Stderr != "ordinary exit" {
		t.Fatalf("incomplete pipe drain: stdout=%d stderr=%q", len(r.Stdout), r.Stderr)
	}
	if r.ExitCode != 1 || !Exit(r.Err, 1) || Interrupted(r.Err) {
		t.Fatalf("ordinary exit misclassified: %+v", r)
	}
}

// A child need not consume all supplied input to complete successfully.
func TestExecuteAllowsEarlyStdinClose(t *testing.T) {
	t.Setenv("FLR_PIPE_HELPER", "closed-input")
	r := Execute(context.Background(), 2*time.Second, strings.Repeat("a", 2<<20), os.Args[0], "-test.run=^TestCommandPipeHelper$")
	if r.Err != nil || r.ExitCode != 0 || string(r.Stdout) != "input declined" {
		t.Fatalf("early stdin close misclassified: %+v", r)
	}
}

// Bounding only stdout/stderr leaves a writer blocked on inherited stdin;
// returning ExitError instead would let optional native operations ignore it.
func TestExecuteBoundsInheritedStdin(t *testing.T) {
	t.Setenv("FLR_PIPE_HELPER", "stdin-parent")
	start := time.Now()
	r := Execute(context.Background(), 2*time.Second, strings.Repeat("a", 2<<20), os.Args[0], "-test.run=^TestCommandPipeHelper$")
	if !errors.Is(r.Err, exec.ErrWaitDelay) || Exit(r.Err, 1) || !Interrupted(r.Err) || r.ExitCode != 1 {
		t.Fatalf("stdin drain timeout misclassified: %+v", r)
	}
	if time.Since(start) > time.Second {
		t.Fatal("stdin drain exceeded cleanup bound")
	}
}

// Cancellation must settle a blocked input writer and both output readers,
// while keeping context cancellation distinguishable from a child exit.
func TestExecuteCancellationWithBlockedPipes(t *testing.T) {
	t.Setenv("FLR_PIPE_HELPER", "sleep")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	timer := time.AfterFunc(100*time.Millisecond, cancel)
	defer timer.Stop()
	start := time.Now()
	r := Execute(ctx, 2*time.Second, strings.Repeat("a", 2<<20), os.Args[0], "-test.run=^TestCommandPipeHelper$")
	if !errors.Is(r.Err, context.Canceled) || !Interrupted(r.Err) {
		t.Fatalf("cancellation misclassified: %+v", r)
	}
	if time.Since(start) > time.Second {
		t.Fatal("cancellation did not settle blocked pipes")
	}
}

func TestExecuteStartFailure(t *testing.T) {
	r := Execute(context.Background(), time.Second, "input", t.TempDir()+"/missing-command")
	if !errors.Is(r.Err, os.ErrNotExist) || !Interrupted(r.Err) || r.ExitCode != -1 {
		t.Fatalf("start failure misclassified: %+v", r)
	}
}
