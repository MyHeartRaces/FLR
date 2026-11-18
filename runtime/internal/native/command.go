// Package native bounds short-lived router operations. It does not own engine
// lifetimes or replace transport probe contexts.
package native

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

var ErrOutputLimit = errors.New("native output limit exceeded")

const OutputLimit = 64 << 10
const DiagnosticLimit = 4096

// Limit is per subprocess, not a transaction deadline or a probe budget.
func Limit(name string) time.Duration {
	switch name {
	case "ubus", "/etc/init.d/firewall", "/etc/init.d/dnsmasq", "/etc/init.d/flr-runtime", "/etc/init.d/flr-proxies", "/usr/sbin/flr-rollback":
		return 30 * time.Second
	case "sing-box", "nft":
		return 10 * time.Second
	default:
		return 2 * time.Second
	}
}

type boundedBuffer struct {
	data      []byte
	limit     int
	truncated bool
}

func (b *boundedBuffer) Write(p []byte) (int, error) {
	n := len(p)
	remaining := b.limit - len(b.data)
	if len(p) > remaining {
		b.truncated = true
		p = p[:remaining]
	}
	b.data = append(b.data, p...)
	return n, nil
}

type Result struct {
	Stdout   []byte
	Stderr   string
	ExitCode int
	Err      error
}

// Own all three pipes so a child exit status cannot hide a drain timeout.
// Passing files to exec also keeps Wait from closing output before it is read.
func runWithPipes(ctx context.Context, cmd *exec.Cmd, input string, out, diag io.Writer, kill func() error) error {
	var pipes [3]struct{ r, w *os.File }
	defer func() {
		for _, p := range pipes {
			if p.r != nil {
				_ = p.r.Close()
				_ = p.w.Close()
			}
		}
	}()
	for i := range pipes {
		r, w, e := os.Pipe()
		if e != nil {
			return e
		}
		pipes[i].r, pipes[i].w = r, w
	}
	cmd.Stdin, cmd.Stdout, cmd.Stderr = pipes[0].r, pipes[1].w, pipes[2].w
	if e := cmd.Start(); e != nil {
		return e
	}
	_ = pipes[0].r.Close()
	_ = pipes[1].w.Close()
	_ = pipes[2].w.Close()

	done := make(chan error, len(pipes))
	copyPipe := func(dst io.Writer, src io.Reader, end *os.File, stdin bool) {
		_, e := io.Copy(dst, src)
		_ = end.Close()
		// Like exec.Cmd, allow a child to stop reading stdin early.
		if stdin && errors.Is(e, syscall.EPIPE) {
			e = nil
		}
		done <- e
	}
	go copyPipe(pipes[0].w, strings.NewReader(input), pipes[0].w, true)
	go copyPipe(out, pipes[1].r, pipes[1].r, false)
	go copyPipe(diag, pipes[2].r, pipes[2].r, false)

	exitErr := cmd.Wait()
	timer := time.NewTimer(250 * time.Millisecond)
	defer timer.Stop()
	var pipeErr error
	for pending := len(pipes); pending > 0; pending-- {
		var interrupted error
		select {
		case e := <-done:
			if pipeErr == nil {
				pipeErr = e
			}
			continue
		case <-ctx.Done():
			interrupted = ctx.Err()
		case <-timer.C:
			interrupted = exec.ErrWaitDelay
		}
		_ = kill()
		// Closing our ends unblocks copies even if an inherited descriptor
		// remains open elsewhere. Join every copy before reading its buffer.
		_ = pipes[0].w.Close()
		_ = pipes[1].r.Close()
		_ = pipes[2].r.Close()
		for ; pending > 0; pending-- {
			<-done
		}
		return interrupted
	}
	if pipeErr != nil {
		return pipeErr
	}
	return exitErr
}

// Execute kills the process group on cancellation, and bounds its pipe
// drains even if the direct child exits while a descendant holds a pipe.
// The finite command is always waited; overflow is an error, never parsed as
// a valid truncated snapshot. Callers must not supply lifetime-managed daemons.
func Execute(ctx context.Context, limit time.Duration, input, name string, args ...string) Result {
	ctx, cancel := context.WithTimeout(ctx, limit)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	kill := func() error {
		if cmd.Process == nil {
			return nil
		}
		e := syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		if e == syscall.ESRCH {
			return nil
		}
		return e
	}
	cmd.Cancel = kill
	cmd.WaitDelay = 250 * time.Millisecond
	out := boundedBuffer{limit: OutputLimit}
	diag := boundedBuffer{limit: DiagnosticLimit}
	e := runWithPipes(ctx, cmd, input, &out, &diag, kill)
	if e != nil {
		_ = kill()
	}
	result := Result{Stdout: out.data, Stderr: string(diag.data), ExitCode: -1}
	if cmd.ProcessState != nil {
		result.ExitCode = cmd.ProcessState.ExitCode()
	}
	if ctx.Err() != nil {
		e = ctx.Err()
	} else if out.truncated || diag.truncated {
		e = ErrOutputLimit
	}
	if e != nil {
		result.Err = fmt.Errorf("%s failed: %w: %s", filepath.Base(name), e, strings.TrimSpace(result.Stderr))
	}
	return result
}

func Run(input, name string, args ...string) error {
	return Execute(context.Background(), Limit(name), input, name, args...).Err
}
func Output(name string, args ...string) ([]byte, error) {
	r := Execute(context.Background(), Limit(name), "", name, args...)
	return r.Stdout, r.Err
}

// Exit reports an ordinary child exit only, excluding deadline/pipe/output
// failures even when that child happened to return the same status.
func Exit(err error, code int) bool {
	var status *exec.ExitError
	return errors.As(err, &status) && status.ExitCode() == code
}

func Interrupted(err error) bool {
	var status *exec.ExitError
	return err != nil && !errors.As(err, &status)
}
