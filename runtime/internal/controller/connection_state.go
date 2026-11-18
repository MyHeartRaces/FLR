package controller

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"

	"github.com/MyHeartRaces/FLR/runtime/internal/connection"
	"github.com/MyHeartRaces/FLR/runtime/internal/privatefile"
)

type connectionCheckpoint struct {
	Version     int    `json:"version"`
	Phase       string `json:"phase"`
	OldRegistry string `json:"old_registry"`
	OldSettings string `json:"old_settings"`
	NewRegistry string `json:"new_registry"`
	NewSettings string `json:"new_settings"`
}

var connectionStageNames = []string{".connection-old-registry.json", ".connection-old-settings.json", ".connection-new-registry.json", ".connection-new-settings.json"}

func commitConnectionState(dir string, registry *connection.Registry, settings Settings, write func(string, []byte) error) error {
	if _, err := os.Lstat(filepath.Join(dir, "connection-state.json")); err == nil {
		return fmt.Errorf("private state recovery required")
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("private checkpoint unavailable")
	}
	newRegistry, newSettings := mustJSON(registry), mustJSON(settings)
	if _, err := validateMigratedPair(newRegistry, newSettings); err != nil {
		return err
	}
	oldRegistry, err := privatefile.Read(filepath.Join(dir, "registry.json"), connection.MaxRegistryBytes)
	if err != nil {
		return fmt.Errorf("current private registry unavailable")
	}
	oldSettings, err := privatefile.Read(filepath.Join(dir, "settings.json"), 1<<20)
	if err != nil {
		return fmt.Errorf("current private settings unavailable")
	}
	if _, err := validateMigratedPair(oldRegistry, oldSettings); err != nil {
		return fmt.Errorf("current state pair rejected")
	}
	if write == nil {
		write = privatefile.Write
	}
	checkpoint := connectionCheckpoint{Version: 2, Phase: "prepared", OldRegistry: stateHash(oldRegistry), OldSettings: stateHash(oldSettings), NewRegistry: stateHash(newRegistry), NewSettings: stateHash(newSettings)}
	stages := [][]byte{oldRegistry, oldSettings, newRegistry, newSettings}
	for i, name := range connectionStageNames {
		if err := write(filepath.Join(dir, name), stages[i]); err != nil {
			return fmt.Errorf("private state staging failed")
		}
	}
	marker := filepath.Join(dir, "connection-state.json")
	rollback := func() error {
		// An ordinary I/O error is not a process crash: revert even if the writer
		// returned an error after publishing its commit marker.
		if err := privatefile.Write(marker, mustJSON(checkpoint)); err != nil {
			return fmt.Errorf("private state recovery pending")
		}
		if err := recoverConnectionState(dir); err != nil {
			return fmt.Errorf("private state recovery pending")
		}
		return fmt.Errorf("private state publication failed; previous state restored")
	}
	if err := write(marker, mustJSON(checkpoint)); err != nil {
		return rollback()
	}
	if err := write(filepath.Join(dir, "registry.json"), newRegistry); err != nil {
		return rollback()
	}
	if err := write(filepath.Join(dir, "settings.json"), newSettings); err != nil {
		return rollback()
	}
	committed := checkpoint
	committed.Phase = "committed"
	if err := write(marker, mustJSON(committed)); err != nil {
		return rollback()
	}
	if err := os.Remove(marker); err != nil {
		return rollback()
	}
	if err := privatefile.SyncDir(dir); err != nil {
		return rollback()
	}
	return nil
}
func recoverConnectionState(dir string) error {
	marker := filepath.Join(dir, "connection-state.json")
	raw, err := privatefile.Read(marker, 4096)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("private state checkpoint rejected")
	}
	var checkpoint connectionCheckpoint
	if err := connection.DecodeStrict(raw, &checkpoint); err != nil || checkpoint.Version != 2 || (checkpoint.Phase != "prepared" && checkpoint.Phase != "committed") {
		return fmt.Errorf("invalid private state checkpoint")
	}
	hashes := []string{checkpoint.OldRegistry, checkpoint.OldSettings, checkpoint.NewRegistry, checkpoint.NewSettings}
	stages := [][]byte{}
	for i, name := range connectionStageNames {
		limit := connection.MaxRegistryBytes
		if i%2 == 1 {
			limit = 1 << 20
		}
		raw, err := privatefile.Read(filepath.Join(dir, name), limit)
		if err != nil || stateHash(raw) != hashes[i] {
			return fmt.Errorf("private state stage rejected")
		}
		stages = append(stages, raw)
	}
	if _, err := validateMigratedPair(stages[0], stages[1]); err != nil {
		return err
	}
	if _, err := validateMigratedPair(stages[2], stages[3]); err != nil {
		return err
	}
	index := 0
	if checkpoint.Phase == "committed" {
		index = 2
	}
	if err := privatefile.Write(filepath.Join(dir, "registry.json"), stages[index]); err != nil {
		return fmt.Errorf("private registry recovery failed")
	}
	if err := privatefile.Write(filepath.Join(dir, "settings.json"), stages[index+1]); err != nil {
		return fmt.Errorf("private settings recovery failed")
	}
	if err := os.Remove(marker); err != nil {
		return fmt.Errorf("private checkpoint cleanup failed")
	}
	return privatefile.SyncDir(dir)
}
func lockPrivateAdmin(dir string) (*os.File, error) {
	path := filepath.Join(dir, "admin.lock")
	if err := privatefile.SafePath(path); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, fmt.Errorf("private state unavailable")
	}
	info, err := os.Stat(dir)
	if err != nil || !info.IsDir() || info.Mode().Perm() != 0700 {
		return nil, fmt.Errorf("private state directory rejected")
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, fmt.Errorf("administrative lock unavailable")
	}
	info, err = file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 {
		file.Close()
		return nil, fmt.Errorf("administrative lock rejected")
	}
	if err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX); err != nil {
		file.Close()
		return nil, fmt.Errorf("administrative lock failed")
	}
	return file, nil
}
