package connection

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"unicode/utf8"

	"github.com/MyHeartRaces/FLR/runtime/internal/control"
	"github.com/MyHeartRaces/FLR/runtime/internal/privatefile"
	"github.com/MyHeartRaces/FLR/runtime/internal/profile"
)

const MaxRegistryBytes = profile.MaxImportBytes * profile.MaxProfiles

type Registry struct {
	Version     int          `json:"version"`
	Connections []Connection `json:"connections"`
}

func DecodeStrict(raw []byte, value any) error {
	if !utf8.Valid(raw) || control.CheckJSON(raw) != nil {
		return fmt.Errorf("invalid or repeated JSON field")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(value); err != nil {
		return fmt.Errorf("invalid connection schema")
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return fmt.Errorf("trailing connection data")
	}
	return nil
}
func ValidateRegistry(r *Registry) error {
	if r == nil || r.Version != 2 || len(r.Connections) > profile.MaxProfiles {
		return fmt.Errorf("invalid connection registry version or capacity")
	}
	ids, revisions := map[string]bool{}, map[string]bool{}
	for _, c := range r.Connections {
		if err := c.Validate(); err != nil || ids[c.ID] || revisions[c.Family+":"+c.Revision] {
			return fmt.Errorf("invalid or repeated connection identity")
		}
		ids[c.ID], revisions[c.Family+":"+c.Revision] = true, true
	}
	return nil
}
func Decode(raw []byte) (*Registry, error) {
	if len(raw) > MaxRegistryBytes {
		return nil, fmt.Errorf("connection registry exceeds size bound")
	}
	var r Registry
	if err := DecodeStrict(raw, &r); err != nil {
		return nil, err
	}
	if err := ValidateRegistry(&r); err != nil {
		return nil, err
	}
	return &r, nil
}
func Load(path string) (*Registry, error) {
	raw, err := privatefile.Read(path, MaxRegistryBytes)
	if os.IsNotExist(err) {
		return &Registry{Version: 2, Connections: []Connection{}}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("private connection registry unavailable")
	}
	return Decode(raw)
}
func (r *Registry) Save(path string) error {
	if err := ValidateRegistry(r); err != nil {
		return err
	}
	raw, err := json.Marshal(r)
	if err != nil || len(raw) > MaxRegistryBytes {
		return fmt.Errorf("connection registry exceeds size bound")
	}
	return privatefile.Write(path, raw)
}
func (r *Registry) Clone() *Registry {
	copy := &Registry{Version: r.Version, Connections: make([]Connection, 0, len(r.Connections))}
	for _, c := range r.Connections {
		copy.Connections = append(copy.Connections, c.Clone())
	}
	return copy
}
func (r *Registry) Summaries() []Summary {
	items := make([]Summary, 0, len(r.Connections))
	for _, c := range r.Connections {
		items = append(items, c.Summary())
	}
	return items
}
func (r *Registry) Import(raw []byte) ([]Summary, error) {
	items, err := ParseImport(raw)
	if err != nil {
		return nil, err
	}
	next := r.Clone()
	for _, item := range items {
		for _, existing := range next.Connections {
			if item.Family == existing.Family && item.Revision == existing.Revision {
				return nil, fmt.Errorf("connection already exists: %s; replace its configuration", existing.ID)
			}
		}
		next.Connections = append(next.Connections, item)
	}
	if err = ValidateRegistry(next); err != nil {
		return nil, err
	}
	r.Connections = next.Connections
	result := make([]Summary, 0, len(items))
	for _, item := range items {
		result = append(result, item.Summary())
	}
	return result, nil
}
func (r *Registry) Replace(id string, raw []byte) error {
	items, err := ParseImport(raw)
	if err != nil || len(items) != 1 {
		return fmt.Errorf("replacement requires exactly one valid connection")
	}
	next := r.Clone()
	for index, old := range next.Connections {
		if old.ID == id {
			item := items[0]
			labels := old.Summary()
			item.ID, item.Name, item.Group, item.Enabled = old.ID, labels.Name, labels.Group, old.Enabled
			if item.Family == "awg" && old.Family == "awg" {
				// The roaming setting belongs to the server, not to the payload.
				item.RoamPorts, item.RoamInterval = old.RoamPorts, old.RoamInterval
			}
			next.Connections[index] = item
			if err = ValidateRegistry(next); err != nil {
				return err
			}
			r.Connections = next.Connections
			return nil
		}
	}
	return fmt.Errorf("connection not found")
}
func (r *Registry) Delete(id string, selection Selection, moveToAuto bool) (Selection, error) {
	if selection.Mode == "connection" && selection.ID == id {
		if !moveToAuto {
			return selection, fmt.Errorf("selected connection requires explicit transition to auto")
		}
		selection = Selection{Mode: "auto"}
	}
	for index, c := range r.Connections {
		if c.ID == id {
			r.Connections = append(r.Connections[:index], r.Connections[index+1:]...)
			return selection, nil
		}
	}
	return selection, fmt.Errorf("connection not found")
}
