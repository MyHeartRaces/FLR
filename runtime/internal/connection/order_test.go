package connection

import "testing"

func TestConnectionOrderAndModes(t *testing.T) {
	a := testConnection(t, testAWG("192.0.2.30:51820"))
	b := testConnection(t, testAWG("192.0.2.40:51820"))
	h := testConnection(t, testURI)
	r := &Registry{Version: 2, Connections: []Connection{a, b, h}}
	order := DefaultOrder(r)
	order.Families = []string{"hy2", "awg", "reality", "vless", "ss2022", "wgws"}
	order.Connections["awg"] = []string{b.ID, a.ID}
	for _, test := range []struct {
		selection Selection
		want      []string
	}{
		{Selection{Mode: "auto"}, []string{h.ID, b.ID, a.ID}},
		{Selection{Mode: "transport", Family: "awg"}, []string{b.ID, a.ID}},
		{Selection{Mode: "connection", ID: a.ID}, []string{a.ID}},
	} {
		items, err := Candidates(r, test.selection, order)
		if err != nil || len(items) != len(test.want) {
			t.Fatal("selection returned wrong candidates", err)
		}
		for i, id := range test.want {
			if items[i].ID != id {
				t.Fatal("explicit order ignored")
			}
		}
	}
	for _, bad := range []Order{
		{Families: []string{"hy2", "hy2"}},
		{Families: []string{"naive"}},
		{Families: order.Families, Connections: map[string][]string{"awg": {h.ID}}},
		{Families: order.Families, Connections: map[string][]string{"awg": {"unknown"}}},
	} {
		if err := ValidateOrder(r, bad); err == nil {
			t.Fatal("invalid family/ID order accepted")
		}
	}
}
func TestPinnedDisableStaysSelected(t *testing.T) {
	c := testConnection(t, testURI)
	c.Enabled = false
	r := &Registry{Version: 2, Connections: []Connection{c}}
	selection := Selection{Mode: "connection", ID: c.ID}
	items, err := Candidates(r, selection, DefaultOrder(r))
	if err != nil || len(items) != 0 || selection.ID != c.ID {
		t.Fatal("disabled pinned connection silently changed selection", err)
	}
}
func TestPinnedDeleteRequiresAuto(t *testing.T) {
	c := testConnection(t, testURI)
	r := &Registry{Version: 2, Connections: []Connection{c}}
	selection := Selection{Mode: "connection", ID: c.ID}
	if _, err := r.Delete(c.ID, selection, false); err == nil || len(r.Connections) != 1 {
		t.Fatal("pinned deletion silently changed mode")
	}
	next, err := r.Delete(c.ID, selection, true)
	if err != nil || next.Mode != "auto" || len(r.Connections) != 0 {
		t.Fatal("explicit delete and auto transition rejected", err)
	}
}
