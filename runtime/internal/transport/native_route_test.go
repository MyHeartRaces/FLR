package transport

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

// The real command boundary is exercised without mutating the host network.
// iproute2 reports protocol 186 as bgp unless numeric output is requested.
func routeCommandFixture(t *testing.T, initial string) string {
	t.Helper()
	dir := t.TempDir()
	state := filepath.Join(dir, "route-state")
	if e := os.WriteFile(state, []byte(initial), 0600); e != nil {
		t.Fatal(e)
	}
	script := `#!/bin/sh
state=$(cat "$FLR_ROUTE_STATE")
case " $* " in
 *" route show exact "*)
  case "$state" in
   absent) echo '[]' ;;
   owned)
    protocol=bgp
    case " $* " in *" -N "*) protocol=186 ;; esac
    printf '[{"dst":"192.0.2.40","gateway":"192.0.2.1","dev":"eth1","protocol":"%s","flags":[]}]\n' "$protocol"
    ;;
   foreign|wrongmark) echo '[{"dst":"192.0.2.40","gateway":"192.0.2.1","dev":"eth1","protocol":"static","flags":[]}]' ;;
   nonwan) echo '[{"dst":"192.0.2.40","dev":"flr_awg","protocol":"static","flags":[]}]' ;;
  esac
  ;;
 *" route get "*)
  if [ "$state" = wrongmark ]; then
   echo '[{"dst":"192.0.2.40","dev":"flr_awg","flags":[]}]'
  else
   echo '[{"dst":"192.0.2.40","gateway":"192.0.2.1","dev":"eth1","flags":[]}]'
  fi
  ;;
 *" route add "*) [ "$state" = absent ] || exit 1; printf owned > "$FLR_ROUTE_STATE" ;;
 *" route del "*) [ "$state" = owned ] || exit 1; printf absent > "$FLR_ROUTE_STATE" ;;
 *) exit 2 ;;
esac
`
	if e := os.WriteFile(filepath.Join(dir, "ip"), []byte(script), 0755); e != nil {
		t.Fatal(e)
	}
	t.Setenv("FLR_ROUTE_STATE", state)
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	return state
}

func requireRouteState(t *testing.T, path, want string) {
	t.Helper()
	got, e := os.ReadFile(path)
	if e != nil || string(got) != want {
		t.Fatalf("route state = %q, want %q: %v", got, want, e)
	}
}

func TestOwnedWANPinLifecycleWithNamedRouteProtocol(t *testing.T) {
	state := routeCommandFixture(t, "absent")
	release, e := (KernelWAN{}).Pin(context.Background(), "eth1", "192.0.2.40")
	if e != nil {
		t.Fatal(e)
	}
	requireRouteState(t, state, "owned")
	if e = release(); e != nil {
		t.Fatal("owned route must be released despite iproute2's bgp name", e)
	}
	requireRouteState(t, state, "absent")
}

func TestExistingWANHostRouteIsReusedAndPreserved(t *testing.T) {
	state := routeCommandFixture(t, "foreign")
	release, e := (KernelWAN{}).Pin(context.Background(), "eth1", "192.0.2.40")
	if e != nil {
		t.Fatal("existing netifd WAN route must allow the same VPS fallback", e)
	}
	if e = release(); e != nil {
		t.Fatal(e)
	}
	requireRouteState(t, state, "foreign")
}

func TestExistingNonWANHostRouteIsRejectedAndPreserved(t *testing.T) {
	state := routeCommandFixture(t, "nonwan")
	if _, e := (KernelWAN{}).Pin(context.Background(), "eth1", "192.0.2.40"); e == nil {
		t.Fatal("foreign tunnel route was accepted as WAN")
	}
	requireRouteState(t, state, "nonwan")
}

func TestBorrowedWANRouteCleanupPreservesForeignRoute(t *testing.T) {
	state := routeCommandFixture(t, "foreign")
	if e := releasePin("eth1", "192.0.2.40"); e != nil {
		t.Fatal("borrowed WAN route must survive journal cleanup without blocking recovery", e)
	}
	requireRouteState(t, state, "foreign")
}

func TestNonWANRouteCannotBeDeletedByOwnedPinCleanup(t *testing.T) {
	state := routeCommandFixture(t, "nonwan")
	if e := releasePin("eth1", "192.0.2.40"); e == nil {
		t.Fatal("foreign tunnel route was accepted as an owned WAN pin")
	}
	requireRouteState(t, state, "nonwan")
}

func TestExistingProtocol186RouteCannotBeBorrowed(t *testing.T) {
	state := routeCommandFixture(t, "owned")
	if _, e := (KernelWAN{}).Pin(context.Background(), "eth1", "192.0.2.40"); e == nil {
		t.Fatal("pre-existing protocol 186 route borrowed with ambiguous journal ownership")
	}
	requireRouteState(t, state, "owned")
}

func TestBorrowedHostRouteStillRequiresMarkedWANLookup(t *testing.T) {
	state := routeCommandFixture(t, "wrongmark")
	if _, e := (KernelWAN{}).Pin(context.Background(), "eth1", "192.0.2.40"); e == nil {
		t.Fatal("WAN host route accepted despite marked lookup entering a tunnel")
	}
	requireRouteState(t, state, "wrongmark")
}
