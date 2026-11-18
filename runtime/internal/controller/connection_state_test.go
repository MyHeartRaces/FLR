package controller

import (
	"fmt"
	"path/filepath"
	"testing"

	"github.com/MyHeartRaces/FLR/runtime/internal/connection"
	"github.com/MyHeartRaces/FLR/runtime/internal/privatefile"
)

func TestConnectionStateCrashRecoversCoherentPair(t *testing.T) {
	for cut := 1; cut <= 8; cut++ {
		t.Run(fmt.Sprint(cut), func(t *testing.T) {
			c := connectionAdmin(t)
			next := c.connections.Clone()
			if _, err := next.Import([]byte(publicConnectionURI)); err != nil {
				t.Fatal(err)
			}
			settings := c.settings
			settings.Order = connection.ReconcileOrder(next, settings.Order)
			writes := 0
			func() {
				defer func() {
					if recover() == nil {
						t.Error("fault did not interrupt publication")
					}
				}()
				_ = commitConnectionState(c.stateDir, next, settings, func(path string, raw []byte) error {
					if err := privatefile.Write(path, raw); err != nil {
						return err
					}
					writes++
					if writes == cut {
						panic("simulated process exit after durable write")
					}
					return nil
				})
			}()
			if err := recoverConnectionState(c.stateDir); err != nil {
				t.Fatal(err)
			}
			r, err := connection.Load(filepath.Join(c.stateDir, "registry.json"))
			s, se := readSettingsAt(c.stateDir)
			want := 4
			if cut == 8 {
				want = 5
			}
			if err != nil || se != nil || len(r.Connections) != want || connection.ValidateOrder(r, s.Order) != nil {
				t.Fatal("crash left mixed pair or wrong commit point")
			}
		})
	}
}
func TestConnectionStateStorageErrorRestoresOldPair(t *testing.T) {
	for cut := 1; cut <= 8; cut++ {
		c := connectionAdmin(t)
		next := c.connections.Clone()
		if _, err := next.Import([]byte(publicConnectionURI)); err != nil {
			t.Fatal(err)
		}
		settings := c.settings
		settings.Order = connection.ReconcileOrder(next, settings.Order)
		writes := 0
		err := commitConnectionState(c.stateDir, next, settings, func(path string, raw []byte) error {
			if err := privatefile.Write(path, raw); err != nil {
				return err
			}
			writes++
			if writes == cut {
				return fmt.Errorf("simulated storage error after write")
			}
			return nil
		})
		if err == nil {
			t.Fatal("injected storage failure reported success")
		}
		r, err := connection.Load(filepath.Join(c.stateDir, "registry.json"))
		s, se := readSettingsAt(c.stateDir)
		if err != nil || se != nil || len(r.Connections) != 4 || connection.ValidateOrder(r, s.Order) != nil {
			t.Fatalf("storage error %d changed old pair", cut)
		}
	}
}
