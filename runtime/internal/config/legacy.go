package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/MyHeartRaces/FLR/runtime/internal/dataplane"
)

// RetireLegacy stops only the fixed FLR compatibility service. Its tracked
// children release nonpersistent TUNs when they exit; a reserved name alone
// never establishes ownership of an interface that remains afterward.
func RetireLegacy() error {
	return retireLegacyWith("/sys/class/net", dataplane.Run)
}

// The filesystem root and native command runner are external boundaries so
// migration can be checked without operating on the host's interfaces.
func retireLegacyWith(netDir string, run func(string, ...string) error) error {
	if e := run("/etc/init.d/flr-proxies", "stop"); e != nil {
		return fmt.Errorf("cannot retire legacy proxy children")
	}
	var remaining []string
	for _, dev := range []string{"flr-hy", "flr-vless"} {
		if _, e := os.Stat(filepath.Join(netDir, dev)); e == nil {
			remaining = append(remaining, dev)
		} else if !os.IsNotExist(e) {
			return fmt.Errorf("cannot inspect legacy interface %s: %w", dev, e)
		}
	}
	if len(remaining) != 0 {
		return fmt.Errorf("legacy interfaces %s remain after stopping flr-proxies; wait for owned children to exit or resolve the name conflict", strings.Join(remaining, ", "))
	}
	return nil
}
