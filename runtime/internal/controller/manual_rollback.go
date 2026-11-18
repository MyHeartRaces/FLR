package controller

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"

	"github.com/MyHeartRaces/FLR/runtime/internal/config"
	"github.com/MyHeartRaces/FLR/runtime/internal/dataplane"
)

type manualRollbackOps struct {
	stateDir  string
	singleton string
	validate  func(string) error
	stop      func() error
	restore   func(string) error
}

func ManualRollback(backup string) error {
	return manualRollbackWith(backup, manualRollbackOps{
		stateDir: StateDir, singleton: "/var/run/flr-runtime/controller.lock",
		validate: config.ValidateBackup,
		stop:     func() error { return dataplane.Run("/etc/init.d/flr-runtime", "stop") },
		restore:  config.RestoreManualRollback,
	})
}

// Stop the live owner before taking any private lock. Then exclude offline
// activation for the entire restore, including generation and guard cleanup.
func manualRollbackWith(backup string, ops manualRollbackOps) error {
	if err := ops.validate(backup); err != nil {
		return err
	}
	if err := ops.stop(); err != nil {
		return fmt.Errorf("cannot stop runtime before manual rollback")
	}
	if err := os.MkdirAll(filepath.Dir(ops.singleton), 0700); err != nil {
		return err
	}
	owner, err := os.OpenFile(ops.singleton, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return err
	}
	defer owner.Close()
	if err := syscall.Flock(int(owner.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		return fmt.Errorf("runtime transition busy; retry manual rollback after activation completes")
	}
	admin, err := lockPrivateAdmin(ops.stateDir)
	if err != nil {
		return err
	}
	defer admin.Close()
	// restore takes rollback.lock last. Startup's recover uses LOCK_NB, so its
	// procd service lock cannot cycle with the native stop inside restoration.
	return ops.restore(backup)
}
