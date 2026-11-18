package controller

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

// Failed singleton acquisition must not consume private recovery state.
func readOwnedSettings(path string, read func() (Settings, error)) (*os.File, Settings, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return nil, Settings{}, err
	}
	lock, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, Settings{}, err
	}
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		lock.Close()
		return nil, Settings{}, fmt.Errorf("another controller owns runtime")
	}
	settings, err := read()
	if err != nil {
		lock.Close()
		return nil, Settings{}, err
	}
	return lock, settings, nil
}
