package config

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

// Only the external service/kernel command boundary is simulated. Interface
// existence and retained state use real files, including for accidental deletes.
type legacyNativeFixture struct {
	t        *testing.T
	netDir   string
	owned    []string
	stopFail bool
	stopped  bool
}

func newLegacyNativeFixture(t *testing.T) *legacyNativeFixture {
	t.Helper()
	return &legacyNativeFixture{t: t, netDir: t.TempDir()}
}

func (f *legacyNativeFixture) add(dev, state string, serviceOwned bool) {
	f.t.Helper()
	dir := filepath.Join(f.netDir, dev)
	if err := os.Mkdir(dir, 0700); err != nil {
		f.t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "state"), []byte(state), 0600); err != nil {
		f.t.Fatal(err)
	}
	if serviceOwned {
		f.owned = append(f.owned, dev)
	}
}

func (f *legacyNativeFixture) run(name string, args ...string) error {
	switch {
	case name == "/etc/init.d/flr-proxies" && reflect.DeepEqual(args, []string{"stop"}):
		f.stopped = true
		if f.stopFail {
			return errors.New("legacy service stop failed")
		}
		// procd closes only its tracked children's nonpersistent TUN handles.
		for _, dev := range f.owned {
			if err := os.RemoveAll(filepath.Join(f.netDir, dev)); err != nil {
				return err
			}
		}
		return nil
	case name == "ip" && len(args) == 4 && reflect.DeepEqual(args[:3], []string{"link", "delete", "dev"}):
		// Model the destructive side effect, so the regression checks retained
		// foreign state instead of merely asserting which command was called.
		return os.RemoveAll(filepath.Join(f.netDir, args[3]))
	default:
		f.t.Fatalf("unexpected native command: %s %v", name, args)
		return errors.New("unexpected native command")
	}
}

func (f *legacyNativeFixture) assertState(dev, want string) {
	f.t.Helper()
	got, err := os.ReadFile(filepath.Join(f.netDir, dev, "state"))
	if err != nil || string(got) != want {
		f.t.Fatalf("interface %s was changed or deleted: state=%q err=%v", dev, got, err)
	}
}

func TestRetireLegacyPreservesForeignInterfaces(t *testing.T) {
	for _, kind := range []string{"bridge", "dummy", "persistent TUN", "foreign nonpersistent TUN"} {
		for _, dev := range []string{"flr-hy", "flr-vless"} {
			t.Run(kind+"/"+dev, func(t *testing.T) {
				f := newLegacyNativeFixture(t)
				f.add(dev, kind+": foreign configuration and traffic", false)
				err := retireLegacyWith(f.netDir, f.run)
				f.assertState(dev, kind+": foreign configuration and traffic")
				if err == nil {
					t.Fatal("remaining interface must block migration")
				}
			})
		}
	}
}

func TestRetireLegacyStopsOwnedChildrenAndAcceptsReleasedTUNs(t *testing.T) {
	f := newLegacyNativeFixture(t)
	f.add("flr-hy", "owned nonpersistent TUN", true)
	f.add("flr-vless", "owned nonpersistent TUN", true)
	if err := retireLegacyWith(f.netDir, f.run); err != nil {
		t.Fatal(err)
	}
	if !f.stopped {
		t.Fatal("legacy service children were not retired")
	}
	for _, dev := range []string{"flr-hy", "flr-vless"} {
		if _, err := os.Stat(filepath.Join(f.netDir, dev)); !os.IsNotExist(err) {
			t.Fatalf("owned child still holds %s: %v", dev, err)
		}
	}
}

func TestRetireLegacyAcceptsAbsentInterfaces(t *testing.T) {
	f := newLegacyNativeFixture(t)
	if err := retireLegacyWith(f.netDir, f.run); err != nil {
		t.Fatal(err)
	}
}

func TestRetireLegacyMixedOwnershipPreservesRemainder(t *testing.T) {
	for _, owned := range []string{"flr-hy", "flr-vless"} {
		t.Run(owned, func(t *testing.T) {
			foreign := "flr-hy"
			if owned == foreign {
				foreign = "flr-vless"
			}
			f := newLegacyNativeFixture(t)
			f.add(owned, "owned nonpersistent TUN", true)
			f.add(foreign, "foreign persistent TUN", false)
			err := retireLegacyWith(f.netDir, f.run)
			f.assertState(foreign, "foreign persistent TUN")
			if err == nil {
				t.Fatal("remaining foreign interface must block migration")
			}
		})
	}
}

func TestRetireLegacyPreservesBothUnknownInterfaces(t *testing.T) {
	f := newLegacyNativeFixture(t)
	f.add("flr-hy", "foreign bridge", false)
	f.add("flr-vless", "foreign dummy", false)
	err := retireLegacyWith(f.netDir, f.run)
	f.assertState("flr-hy", "foreign bridge")
	f.assertState("flr-vless", "foreign dummy")
	if err == nil {
		t.Fatal("remaining foreign interfaces must block migration")
	}
}

func TestRetireLegacyStopFailurePreservesAllInterfaces(t *testing.T) {
	f := newLegacyNativeFixture(t)
	f.add("flr-hy", "owned nonpersistent TUN", true)
	f.add("flr-vless", "foreign persistent TUN", false)
	f.stopFail = true
	if err := retireLegacyWith(f.netDir, f.run); err == nil {
		t.Fatal("service stop failure must block migration")
	}
	f.assertState("flr-hy", "owned nonpersistent TUN")
	f.assertState("flr-vless", "foreign persistent TUN")
}

func TestRetireLegacyInspectionFailureBlocksMigration(t *testing.T) {
	f := newLegacyNativeFixture(t)
	// A symlink loop makes Stat fail with an inspection error, not absence,
	// without depending on privileges or host network state.
	if err := os.Symlink("flr-hy", filepath.Join(f.netDir, "flr-hy")); err != nil {
		t.Fatal(err)
	}
	f.add("flr-vless", "foreign persistent TUN", false)
	if err := retireLegacyWith(f.netDir, f.run); err == nil {
		t.Fatal("interface inspection failure must block migration")
	}
	f.assertState("flr-vless", "foreign persistent TUN")
}
