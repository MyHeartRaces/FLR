package controller

import "testing"

func TestConnectionUpdateSetsAWGRoamWithoutNewChoice(t *testing.T) {
	c := connectionAdmin(t)
	var awgID, proxyID string
	for _, item := range c.connections.Connections {
		if item.Family == "awg" && awgID == "" {
			awgID = item.ID
		} else if item.Family != "awg" && proxyID == "" {
			proxyID = item.ID
		}
	}
	if awgID == "" {
		t.Skip("fixture has no AWG connection")
	}
	epoch := c.choiceEpoch
	update := func(id string, meta map[string]any) error {
		_, err := c.HandleAPI(connectionRequest(t, c, "connection-update", map[string]any{"id": id, "metadata": meta}))
		return err
	}
	if err := update(awgID, map[string]any{"roam_ports": "40000-40999", "roam_interval": 900}); err != nil {
		t.Fatal(err)
	}
	var revision string
	for _, item := range c.connections.Connections {
		if item.ID == awgID {
			if item.RoamPorts != "40000-40999" || item.RoamInterval != 900 {
				t.Fatalf("roam not stored: %q %d", item.RoamPorts, item.RoamInterval)
			}
			revision = item.Revision
		}
	}
	if c.choiceEpoch != epoch {
		t.Fatal("a roam setting must not start a new choice")
	}
	for _, bad := range []map[string]any{{"roam_ports": "80-90"}, {"roam_ports": "40000-60000"}, {"roam_interval": 5}} {
		if update(awgID, bad) == nil {
			t.Fatalf("accepted %v", bad)
		}
	}
	if proxyID != "" && update(proxyID, map[string]any{"roam_ports": "40000-40999"}) == nil {
		t.Fatal("roaming accepted for a non-AWG connection")
	}
	if err := update(awgID, map[string]any{"roam_ports": "", "roam_interval": 0}); err != nil {
		t.Fatal(err)
	}
	for _, item := range c.connections.Connections {
		if item.ID == awgID && (item.RoamPorts != "" || item.Revision != revision) {
			t.Fatalf("roam not cleared or revision changed: %q %s", item.RoamPorts, item.Revision)
		}
	}
}

// LuCI's «Вернуться к «Авто»» sends {"mode":"auto"} after a connection was
// pinned; the stored id must not survive into the new selection.
func TestSelectionAutoAfterConnectionSelection(t *testing.T) {
	c := connectionAdmin(t)
	id := c.connections.Connections[0].ID
	if _, err := c.HandleAPI(connectionRequest(t, c, "selection", map[string]any{"selection": map[string]any{"mode": "connection", "id": id}})); err != nil {
		t.Fatal(err)
	}
	if c.settings.Selection.Mode != "connection" || c.settings.Selection.ID != id {
		t.Fatalf("connection selection not stored: %+v", c.settings.Selection)
	}
	if _, err := c.HandleAPI(connectionRequest(t, c, "selection", map[string]any{"selection": map[string]any{"mode": "auto"}})); err != nil {
		t.Fatalf("auto after a connection selection rejected: %v", err)
	}
	if c.settings.Selection.Mode != "auto" || c.settings.Selection.ID != "" || c.settings.Selection.Family != "" {
		t.Fatalf("stale selection fields kept: %+v", c.settings.Selection)
	}
}
