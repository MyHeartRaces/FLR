package controller

import (
	"fmt"
	"github.com/MyHeartRaces/FLR/runtime/internal/contract"
	"github.com/MyHeartRaces/FLR/runtime/internal/dataplane"
	"path/filepath"
)

type devicePolicyOps struct {
	block  func(string, bool) error
	update func(map[string]contract.Class) error
	clear  func(string) error
	save   func(string, any) error
}

func (c *Controller) handleDevice(client, value string) (any, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	ops := c.deviceOps
	if ops == nil {
		ops = &devicePolicyOps{dataplane.BlockDevice, dataplane.UpdateProfiles, dataplane.ClearDevice, WriteJSON}
	}
	s := c.settings
	profiles := map[string]contract.Class{}
	for ip, class := range s.Options.Profiles {
		profiles[ip] = class
	}
	if value == "auto" {
		delete(profiles, client)
	} else {
		profiles[client] = contract.Class(value)
	}
	// Keep the gate on every failure after quiescence. Retrying any policy for
	// this device completes cleanup; no success is reported with cleanup pending.
	if e := ops.block(client, true); e != nil {
		return nil, fmt.Errorf("cannot prepare device transition; retry device policy")
	}
	if e := ops.update(profiles); e != nil {
		return nil, fmt.Errorf("device traffic blocked; policy update failed, retry device policy")
	}
	if e := ops.clear(client); e != nil {
		return nil, fmt.Errorf("device traffic blocked; connection cleanup failed, retry device policy")
	}
	s.Options.Profiles = profiles
	if e := ops.save(filepath.Join(c.stateDir, "settings.json"), s); e != nil {
		return nil, fmt.Errorf("device traffic blocked; settings save failed, retry device policy")
	}
	// Persisted intent becomes authoritative even if opening the gate fails.
	c.settings = s
	c.generation++
	if e := ops.block(client, false); e != nil {
		return nil, fmt.Errorf("device policy saved but traffic blocked; retry device policy")
	}
	return map[string]any{"devices": profiles}, nil
}
