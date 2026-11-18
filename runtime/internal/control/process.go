package control

import (
	"context"
	"fmt"
	"github.com/MyHeartRaces/FLR/runtime/internal/dataplane"
	"io"
	"os"
	"os/exec"
	"sync"
	"syscall"
	"time"
)

type ProcessBackend struct {
	WAN    string
	mu     sync.Mutex
	id     string
	cancel context.CancelFunc
	done   chan error
}

func (b *ProcessBackend) Start(ctx context.Context, s Session) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.id != "" {
		return fmt.Errorf("direct worker already active")
	}
	if e := dataplane.SessionGuard(s.Client, s.MAC); e != nil {
		return e
	}
	child, cancel := context.WithDeadline(ctx, s.Expires)
	r, w, e := os.Pipe()
	if e != nil {
		cancel()
		_ = dataplane.ClearSession()
		return e
	}
	defer r.Close()
	cmd := exec.CommandContext(child, "/usr/sbin/flr-controller", "direct-worker", "--client", s.Client, "--mac", s.MAC, "--session-id", s.ID, "--expires", s.Expires.Format(time.RFC3339Nano), "--wan", b.WAN)
	cmd.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGTERM}
	cmd.ExtraFiles = []*os.File{w}
	if e = cmd.Start(); e != nil {
		w.Close()
		cancel()
		_ = dataplane.ClearSession()
		return e
	}
	w.Close()
	done := make(chan error, 1)
	go func() {
		done <- cmd.Wait()
		b.mu.Lock()
		defer b.mu.Unlock()
		if b.id == s.ID {
			_ = dataplane.ClearSession()
		}
	}()
	r.SetReadDeadline(time.Now().Add(5 * time.Second))
	ready := make([]byte, 5)
	_, e = io.ReadFull(r, ready)
	if e != nil || string(ready) != "ready" {
		cancel()
		<-done
		_ = dataplane.ClearSession()
		return fmt.Errorf("direct worker failed to start")
	}
	b.id = s.ID
	b.cancel = cancel
	b.done = done
	return nil
}
func (b *ProcessBackend) Stop(s Session) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.id != s.ID {
		return nil
	}
	b.cancel()
	<-b.done
	b.id = ""
	return dataplane.ClearSession()
}
