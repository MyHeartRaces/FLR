package connection

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/MyHeartRaces/FLR/runtime/internal/config"
	"github.com/MyHeartRaces/FLR/runtime/internal/profile"
)

func ParseImport(raw []byte) ([]Connection, error) {
	if len(raw) == 0 || len(raw) > profile.MaxImportBytes {
		return nil, fmt.Errorf("connection import requires 1..1048576 bytes")
	}
	items, err := parseImport(bytes.TrimSpace(raw), 0)
	if err != nil {
		return nil, err
	}
	if len(items) == 0 {
		return nil, fmt.Errorf("connection import is empty")
	}
	if err = ValidateRegistry(&Registry{Version: 2, Connections: items}); err != nil {
		return nil, err
	}
	return items, nil
}
func parseImport(raw []byte, depth int) ([]Connection, error) {
	if depth > 3 || len(raw) == 0 {
		return nil, fmt.Errorf("invalid connection import nesting")
	}
	if raw[0] == '[' && !isAWGImport(raw) {
		var list []json.RawMessage
		if err := DecodeStrict(raw, &list); err != nil {
			return nil, err
		}
		items := []Connection{}
		for index, entry := range list {
			parsed, err := parseImport(bytes.TrimSpace(entry), depth+1)
			if err != nil {
				return nil, fmt.Errorf("connection import item %d rejected", index+1)
			}
			items = append(items, parsed...)
			if len(items) > profile.MaxProfiles {
				return nil, fmt.Errorf("connection import exceeds capacity")
			}
		}
		return items, nil
	}
	if raw[0] == '"' {
		var text string
		if err := DecodeStrict(raw, &text); err != nil {
			return nil, err
		}
		return parseImport(bytes.TrimSpace([]byte(text)), depth+1)
	}
	if isAWGImport(raw) {
		fields, err := config.ParseAWG(raw)
		if err != nil {
			return nil, fmt.Errorf("AWG import rejected")
		}
		id, err := NewID()
		if err != nil {
			return nil, err
		}
		c := Connection{ID: id, Name: "awg-" + fields["Endpoint"], Family: "awg", Enabled: true, AWG: fields}
		c.Revision, err = c.payloadRevision()
		if err != nil {
			return nil, err
		}
		return []Connection{c}, nil
	}
	profiles, err := profile.Parse(raw)
	if err != nil {
		return nil, err
	}
	items := make([]Connection, 0, len(profiles))
	for _, p := range profiles {
		id, err := NewID()
		if err != nil {
			return nil, err
		}
		c, err := FromProfile(p, id)
		if err != nil {
			return nil, err
		}
		items = append(items, c)
	}
	return items, nil
}

func isAWGImport(raw []byte) bool {
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		return line == "[Interface]"
	}
	return false
}
