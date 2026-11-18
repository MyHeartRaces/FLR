package profile

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestMetadataImportBoundariesAndTypes(t *testing.T) {
	for _, test := range []struct {
		priority any
		group    any
		valid    bool
	}{
		{-1000000, strings.Repeat("a", 80), true}, {1000000, strings.Repeat("Ж", 40), true}, {-1, "Сервер / A", true},
		{-1000001, "x", false}, {1000001, "x", false}, {1.5, "x", false}, {0, strings.Repeat("Ж", 41), false}, {0, 42, false}, {0, "x\ny", false}, {0, "https://token", false},
	} {
		var bundle map[string]any
		json.Unmarshal(fixture(t, "bundle.json"), &bundle)
		record := bundle["profiles"].([]any)[0].(map[string]any)
		delete(record, "tracegate")
		record["server_group"] = test.group
		record["priority"] = test.priority
		raw, _ := json.Marshal(bundle)
		p, e := Parse(raw)
		if (e == nil) != test.valid {
			t.Fatalf("metadata validation mismatch: %v", e)
		}
		if e == nil && (len(p) != 1 || p[0].ServerGroup != test.group) {
			t.Fatal("valid metadata changed")
		}
	}
}
