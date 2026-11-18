//go:build linux

package engineupdate

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
)

func hardenChild(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGTERM, Setpgid: true}
}

// listenerInode requires a unique IPv4 LISTEN entry at the canary address and
// an open descriptor for that socket in the child itself.
func listenerInode(pid, port int) (string, error) {
	f, err := os.Open("/proc/net/tcp")
	if err != nil {
		return "", err
	}
	defer f.Close()
	addr := fmt.Sprintf("%08X:%04X", binary.NativeEndian.Uint32([]byte{127, 0, 0, 1}), port)
	var inode string
	lines := bufio.NewScanner(f)
	for lines.Scan() {
		fields := strings.Fields(lines.Text())
		if len(fields) < 10 || fields[1] != addr || fields[3] != "0A" {
			continue
		}
		if inode != "" || fields[9] == "0" {
			return "", errors.New("canary listener inode is ambiguous")
		}
		inode = fields[9]
	}
	if err := lines.Err(); err != nil {
		return "", err
	}
	if inode == "" {
		return "", errors.New("loopback canary listener not found")
	}
	dir := fmt.Sprintf("/proc/%d/fd", pid)
	fds, err := os.ReadDir(dir)
	if err != nil {
		return "", err
	}
	socket := "socket:[" + inode + "]"
	for _, fd := range fds {
		target, err := os.Readlink(filepath.Join(dir, fd.Name()))
		if err == nil && target == socket {
			return inode, nil
		}
	}
	return "", errors.New("canary child does not own the listener")
}
