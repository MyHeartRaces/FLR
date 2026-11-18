//go:build !linux

package engineupdate

import (
	"errors"
	"os/exec"
)

func hardenChild(cmd *exec.Cmd) {}

func listenerInode(pid, port int) (string, error) {
	return "", errors.New("canary listener ownership requires Linux procfs")
}
