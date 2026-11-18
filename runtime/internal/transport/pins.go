package transport

import (
	"encoding/json"
	"fmt"
	"github.com/MyHeartRaces/FLR/runtime/internal/native"
	"net"
	"os"
	"path/filepath"
	"regexp"

	"github.com/MyHeartRaces/FLR/runtime/internal/dataplane"
)

const pinJournal = RuntimeDir + "/wan-pins.json"

type pins struct {
	WAN       string   `json:"wan"`
	Addresses []string `json:"addresses"`
}

func savePins(wan string, addresses []string) error {
	if e := privateDir(RuntimeDir); e != nil {
		return e
	}
	b, e := json.Marshal(pins{WAN: wan, Addresses: addresses})
	if e != nil {
		return e
	}
	f, e := os.CreateTemp(RuntimeDir, ".pins-*")
	if e != nil {
		return e
	}
	defer os.Remove(f.Name())
	if e = f.Chmod(0600); e == nil {
		_, e = f.Write(b)
	}
	if e == nil {
		e = f.Sync()
	}
	ce := f.Close()
	if e != nil {
		return e
	}
	if ce != nil {
		return ce
	}
	if e = os.Rename(f.Name(), pinJournal); e != nil {
		return e
	}
	dir, e := os.Open(filepath.Dir(pinJournal))
	if e != nil {
		return e
	}
	defer dir.Close()
	return dir.Sync()
}
func releasePin(wan, address string) error {
	raw, e := native.Output("ip", "-N", "-j", "-4", "route", "show", "exact", address+"/32")
	if e != nil {
		return fmt.Errorf("cannot inspect owned WAN pin")
	}
	var routes []map[string]any
	if json.Unmarshal(raw, &routes) != nil {
		return fmt.Errorf("invalid WAN route snapshot")
	}
	if len(routes) == 0 {
		return nil
	}
	if len(routes) != 1 || routes[0]["dev"] != wan {
		return fmt.Errorf("WAN pin conflicts with foreign route")
	}
	protocol := fmt.Sprint(routes[0]["protocol"])
	if protocol != "186" {
		// A borrowed netifd WAN route is journaled before startup too. Preserve
		// it during stop/recovery; only numeric protocol 186 is ours to delete.
		return nil
	}
	return dataplane.Run("ip", "-4", "route", "del", address+"/32", "dev", wan, "proto", "186")
}

// CleanupStalePins uses the private pre-add journal plus exact route protocol
// and interface checks. It never flushes a protocol-wide or foreign route set.
func CleanupStalePins() error {
	info, e := os.Lstat(pinJournal)
	if os.IsNotExist(e) {
		return nil
	}
	if e != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || info.Size() > 8192 {
		return fmt.Errorf("unsafe WAN pin journal")
	}
	b, e := os.ReadFile(pinJournal)
	if e != nil {
		return e
	}
	var p pins
	if json.Unmarshal(b, &p) != nil || !regexp.MustCompile(`^[a-zA-Z0-9_.:-]{1,15}$`).MatchString(p.WAN) || len(p.Addresses) > 8 {
		return fmt.Errorf("invalid WAN pin journal")
	}
	for _, address := range p.Addresses {
		ip := net.ParseIP(address)
		if ip == nil || ip.To4() == nil {
			return fmt.Errorf("invalid WAN pin journal address")
		}
		if e = releasePin(p.WAN, address); e != nil {
			return e
		}
	}
	return os.Remove(pinJournal)
}
