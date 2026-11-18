package qos

import (
	"fmt"
	"strings"
	"testing"
)

type fakeTC struct {
	calls  []string
	qdisc  map[string]string
	failOn string
}

func (f *fakeTC) run(name string, args ...string) ([]byte, error) {
	line := name + " " + strings.Join(args, " ")
	f.calls = append(f.calls, line)
	if f.failOn != "" && strings.Contains(line, f.failOn) {
		return []byte("RTNETLINK answers: Operation not supported"), fmt.Errorf("exit 2")
	}
	if name == "tc" && len(args) >= 4 && args[0] == "qdisc" && args[1] == "show" {
		return []byte(f.qdisc[args[3]]), nil
	}
	if name == "tc" && args[0] == "qdisc" && args[1] == "replace" {
		dev := args[3]
		if args[4] == "handle" {
			f.qdisc[dev] += "qdisc ingress ffff: parent ffff:fff1\n"
		} else {
			f.qdisc[dev] += "qdisc cake 8001: root bandwidth\n"
		}
	}
	if name == "tc" && args[0] == "qdisc" && args[1] == "del" {
		f.qdisc[args[3]] = ""
	}
	return nil, nil
}

func TestValidate(t *testing.T) {
	for _, c := range []Config{{Enabled: true}, {Enabled: true, UploadKbit: 999}, {UploadKbit: 20000000}} {
		if c.Validate() == nil {
			t.Fatalf("accepted %+v", c)
		}
	}
	for _, c := range []Config{{}, {Enabled: true, UploadKbit: 45000}, {Enabled: true, DownloadKbit: 90000, UploadKbit: 0}} {
		if e := c.Validate(); e != nil {
			t.Fatal(c, e)
		}
	}
}

func TestReconcileInstallsKeepsAndRemoves(t *testing.T) {
	f := &fakeTC{qdisc: map[string]string{}}
	m := &Manager{Run: f.run}
	c := Config{Enabled: true, UploadKbit: 45000, DownloadKbit: 90000}
	if e := m.Reconcile(c, false); e != nil || len(f.calls) != 0 {
		t.Fatal("must wait for the tunnel interface", e, f.calls)
	}
	if e := m.Reconcile(c, true); e != nil {
		t.Fatal(e)
	}
	joined := strings.Join(f.calls, "\n")
	for _, want := range []string{"tc qdisc replace dev flr_awg root cake bandwidth 45000kbit besteffort triple-isolate nat", "ip link add name flr_ifb type ifb", "action mirred egress redirect dev flr_ifb", "tc qdisc replace dev flr_ifb root cake bandwidth 90000kbit besteffort triple-isolate nat ingress"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("missing %q in\n%s", want, joined)
		}
	}
	n := len(f.calls)
	if e := m.Reconcile(c, true); e != nil || len(f.calls) != n+2 {
		t.Fatalf("present config must only be inspected: %v", f.calls[n:])
	}
	// netifd recreated flr_awg: the cake root is gone and is reinstalled.
	f.qdisc[Device] = ""
	if e := m.Reconcile(c, true); e != nil || !strings.Contains(strings.Join(f.calls[n+2:], "\n"), "root cake bandwidth 45000kbit") {
		t.Fatal("lost qdisc not reinstalled", e)
	}
	n = len(f.calls)
	if e := m.Reconcile(Config{}, true); e != nil {
		t.Fatal(e)
	}
	joined = strings.Join(f.calls[n:], "\n")
	for _, want := range []string{"tc qdisc del dev flr_awg root", "tc qdisc del dev flr_awg ingress", "ip link del flr_ifb"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("missing removal %q", want)
		}
	}
	n = len(f.calls)
	if e := m.Reconcile(Config{}, true); e != nil || len(f.calls) != n {
		t.Fatal("disabled and not owned must do nothing")
	}
}

func TestReconcileReportsUnsupportedKernel(t *testing.T) {
	f := &fakeTC{qdisc: map[string]string{}, failOn: "cake"}
	m := &Manager{Run: f.run}
	if e := m.Reconcile(Config{Enabled: true, UploadKbit: 45000}, true); e == nil || !strings.Contains(e.Error(), "not applied") {
		t.Fatal(e)
	}
	f.failOn = ""
	if e := m.Reconcile(Config{}, true); e != nil || !strings.Contains(strings.Join(f.calls, "\n"), "ip link del flr_ifb") {
		t.Fatal("a partial install must be cleaned up when turned off")
	}
}

func TestRemovalKeepsOwnershipUntilTheRedirectIsGone(t *testing.T) {
	f := &fakeTC{qdisc: map[string]string{}}
	m := &Manager{Run: f.run}
	if e := m.Reconcile(Config{Enabled: true, DownloadKbit: 90000}, true); e != nil {
		t.Fatal(e)
	}
	f.failOn = "del dev flr_awg ingress"
	n := len(f.calls)
	if e := m.Reconcile(Config{}, true); e == nil || !m.owned {
		t.Fatal("a failed ingress removal must be reported and retried")
	}
	if strings.Contains(strings.Join(f.calls[n:], "\n"), "ip link del flr_ifb") {
		t.Fatal("ifb deleted while the ingress redirect may still point at it")
	}
	f.failOn = ""
	if e := m.Reconcile(Config{}, true); e != nil || m.owned {
		t.Fatal("retry must finish the removal", e)
	}
}
