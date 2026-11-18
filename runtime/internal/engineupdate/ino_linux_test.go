//go:build linux

package engineupdate

import (
	"net"
	"os"
	"os/exec"
	"syscall"
	"testing"
)

func statIno(st os.FileInfo) uint64 { return st.Sys().(*syscall.Stat_t).Ino }

func TestListenerInodeRequiresChildFD(t *testing.T) {
	l, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	port := l.Addr().(*net.TCPAddr).Port
	if _, err := listenerInode(os.Getpid(), port); err != nil {
		t.Fatalf("cannot verify actual owner: %v", err)
	}
	other := exec.Command("sleep", "30")
	if err := other.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		other.Process.Kill()
		other.Wait()
	}()
	if _, err := listenerInode(other.Process.Pid, port); err == nil {
		t.Fatal("listener attributed to unrelated child")
	}
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := listenerInode(os.Getpid(), port); err == nil {
		t.Fatal("closed listener still attributed to process")
	}
}
