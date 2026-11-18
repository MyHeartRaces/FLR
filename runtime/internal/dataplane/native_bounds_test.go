package dataplane

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// These helpers never execute router tools. The existing test executable is
// the child, including the descendant which deliberately inherits its pipes.
func TestNativeBoundsHelper(t *testing.T) {
	mode := os.Getenv("FLR_BOUNDS_HELPER")
	if mode == "" {
		return
	}
	switch mode {
	case "empty", "empty-timeout":
		fmt.Fprintln(os.Stderr, "conntrack v1.4.8 (conntrack-tools): 0 flow entries have been deleted.")
		if mode == "empty-timeout" {
			time.Sleep(4 * time.Second)
		}
		os.Exit(1)
	case "bad-exit-one":
		fmt.Fprintln(os.Stderr, "permission denied")
		os.Exit(1)
	case "partial-sleep":
		if e := os.WriteFile(os.Getenv("FLR_BOUNDS_MARKER"), []byte("partial"), 0600); e != nil {
			os.Exit(3)
		}
		time.Sleep(4 * time.Second)
	case "sleep":
		time.Sleep(4 * time.Second)
	case "output":
		fmt.Print(strings.Repeat("x", 2<<20))
	case "diagnostic":
		fmt.Fprint(os.Stderr, strings.Repeat("x", 2<<20))
		os.Exit(2)
	case "parent", "empty-parent":
		cmd := exec.Command(os.Args[0], "-test.run=^TestNativeBoundsHelper$")
		cmd.Env = append(os.Environ(), "FLR_BOUNDS_HELPER=descendant")
		cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
		if e := cmd.Start(); e != nil {
			os.Exit(3)
		}
		if mode == "empty-parent" {
			fmt.Fprintln(os.Stderr, "conntrack v1.4.8 (conntrack-tools): 0 flow entries have been deleted.")
			os.Exit(1)
		}
	case "descendant":
		time.Sleep(4 * time.Second)
		if e := os.WriteFile(os.Getenv("FLR_BOUNDS_MARKER"), []byte("survived"), 0600); e != nil {
			os.Exit(3)
		}
	}
	os.Exit(0)
}

func TestNativeRunBoundsExecution(t *testing.T) {
	t.Setenv("FLR_BOUNDS_HELPER", "sleep")
	start := time.Now()
	e := Run(os.Args[0], "-test.run=^TestNativeBoundsHelper$")
	if !errors.Is(e, context.DeadlineExceeded) || time.Since(start) > 3*time.Second {
		t.Fatalf("unbounded or misclassified command: elapsed=%s error=%v", time.Since(start), e)
	}
}

func TestNativeOutputRejectsOverflow(t *testing.T) {
	t.Setenv("FLR_BOUNDS_HELPER", "output")
	b, e := output(os.Args[0], "-test.run=^TestNativeBoundsHelper$")
	if e == nil || len(b) > 64<<10 {
		t.Fatalf("oversized output accepted: bytes=%d error=%v", len(b), e)
	}
}

func TestNativeFailureDiagnosticsBounded(t *testing.T) {
	t.Setenv("FLR_BOUNDS_HELPER", "diagnostic")
	e := Run(os.Args[0], "-test.run=^TestNativeBoundsHelper$")
	if e == nil || len(e.Error()) > 8192 {
		t.Fatal("failure diagnostics not bounded")
	}
}

func TestNativeRunReapsPipeHoldingDescendant(t *testing.T) {
	t.Setenv("FLR_BOUNDS_HELPER", "parent")
	marker := filepath.Join(t.TempDir(), "descendant")
	t.Setenv("FLR_BOUNDS_MARKER", marker)
	start := time.Now()
	e := Run(os.Args[0], "-test.run=^TestNativeBoundsHelper$")
	if e == nil || time.Since(start) > 3*time.Second {
		t.Errorf("inherited pipe escaped deadline: elapsed=%s error=%v", time.Since(start), e)
	}
	// The helper has a finite lifetime even on the RED baseline.
	time.Sleep(time.Until(start.Add(4500 * time.Millisecond)))
	if _, e := os.Stat(marker); !os.IsNotExist(e) {
		t.Fatal("descendant survived command cleanup")
	}
}

func TestPreservedBackupRejectsSymlink(t *testing.T) {
	dir := privateBackupDir(t)
	for _, name := range []string{"network", "firewall", "dhcp"} {
		if e := os.WriteFile(filepath.Join(dir, name), []byte("synthetic configuration"), 0600); e != nil {
			t.Fatal(e)
		}
	}
	if e := ValidateBackup(dir); e != nil {
		t.Fatal(e)
	}
	outside := filepath.Join(t.TempDir(), "network")
	if e := os.Rename(filepath.Join(dir, "network"), outside); e != nil {
		t.Fatal(e)
	}
	if e := os.Symlink(outside, filepath.Join(dir, "network")); e != nil {
		t.Fatal(e)
	}
	if e := ValidateBackup(dir); e == nil {
		t.Fatal("symlink restoration snapshot accepted")
	}
}

func TestConntrackExitOneRequiresVerifiedEmptyResult(t *testing.T) {
	binary, e := os.Executable()
	if e != nil {
		t.Fatal(e)
	}
	dir := t.TempDir()
	if e = os.WriteFile(filepath.Join(dir, "conntrack"), []byte("#!/bin/sh\nexec \"$FLR_TEST_BINARY\" -test.run=^TestNativeBoundsHelper$\n"), 0700); e != nil {
		t.Fatal(e)
	}
	t.Setenv("PATH", dir)
	t.Setenv("FLR_TEST_BINARY", binary)
	for _, mode := range []string{"empty", "bad-exit-one", "empty-timeout", "empty-parent"} {
		t.Run(mode, func(t *testing.T) {
			t.Setenv("FLR_BOUNDS_HELPER", mode)
			t.Setenv("FLR_BOUNDS_MARKER", filepath.Join(t.TempDir(), "descendant"))
			e := ClearSlot()
			if (e == nil) != (mode == "empty") {
				t.Fatalf("incorrect cleanup result for %s: %v", mode, e)
			}
			if mode == "empty-parent" && !errors.Is(e, exec.ErrWaitDelay) {
				t.Fatal("pipe drain timeout was not retained", e)
			}
			if mode == "empty-timeout" && !errors.Is(e, context.DeadlineExceeded) {
				t.Fatal("deadline was not retained", e)
			}
		})
	}
}
