package controller

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func TestStartupReadsSettingsOnlyAfterSingletonOwnership(t *testing.T) {
	path := filepath.Join(t.TempDir(), "private", "controller.lock")
	reads := 0
	read := func() (Settings, error) { reads++; return DefaultSettings(), nil }
	owner, _, err := readOwnedSettings(path, read)
	if err != nil || reads != 1 {
		t.Fatal("owner could not read settings", err)
	}
	if contender, _, err := readOwnedSettings(path, read); err == nil || contender != nil || reads != 1 {
		t.Fatal("excluded startup consumed settings or recovery intent", err)
	}
	if err := owner.Close(); err != nil {
		t.Fatal(err)
	}
	if lock, _, err := readOwnedSettings(path, func() (Settings, error) { return Settings{}, fmt.Errorf("public recovery failure") }); err == nil || lock != nil {
		t.Fatal("failed recovery admitted startup")
	}
	owner, _, err = readOwnedSettings(path, read)
	if err != nil || reads != 2 {
		t.Fatal("failed recovery retained singleton ownership", err)
	}
	other, err := os.OpenFile(path, os.O_RDWR, 0600)
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	if err := syscall.Flock(int(other.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err == nil {
		t.Fatal("startup released singleton before caller lifecycle completed")
	}
	owner.Close()
}
