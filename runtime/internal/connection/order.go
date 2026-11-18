package connection

import "fmt"

type Selection struct {
	Mode   string `json:"mode"`
	Family string `json:"family,omitempty"`
	ID     string `json:"id,omitempty"`
}
type Order struct {
	Families    []string            `json:"families"`
	Connections map[string][]string `json:"connections"`
}

func ValidateSelection(s Selection) error {
	switch s.Mode {
	case "auto":
		if s.ID == "" && s.Family == "" {
			return nil
		}
	case "transport":
		if s.ID == "" && KnownFamily(s.Family) {
			return nil
		}
	case "connection":
		if s.Family == "" && identityPattern.MatchString(s.ID) {
			return nil
		}
	}
	return fmt.Errorf("invalid connection selection")
}
func ValidateFamilies(families []string) error {
	if len(families) != len(Families) {
		return fmt.Errorf("family order must contain every supported protocol")
	}
	seen := map[string]bool{}
	for _, family := range families {
		if !KnownFamily(family) || seen[family] {
			return fmt.Errorf("invalid or repeated family order")
		}
		seen[family] = true
	}
	return nil
}
func DefaultOrder(r *Registry) Order {
	order := Order{Families: append([]string{}, Families...), Connections: map[string][]string{}}
	for _, family := range Families {
		order.Connections[family] = []string{}
	}
	for _, c := range r.Connections {
		order.Connections[c.Family] = append(order.Connections[c.Family], c.ID)
	}
	return order
}
func ValidateOrder(r *Registry, order Order) error {
	if err := ValidateRegistry(r); err != nil {
		return err
	}
	if err := ValidateFamilies(order.Families); err != nil {
		return err
	}
	ids := map[string]string{}
	for _, c := range r.Connections {
		ids[c.ID] = c.Family
	}
	seen := map[string]bool{}
	for family, list := range order.Connections {
		if !KnownFamily(family) {
			return fmt.Errorf("unknown connection order protocol")
		}
		for _, id := range list {
			if ids[id] != family || seen[id] {
				return fmt.Errorf("unknown, repeated or cross-protocol connection order")
			}
			seen[id] = true
		}
	}
	if len(seen) != len(ids) {
		return fmt.Errorf("connection order must contain every connection")
	}
	return nil
}

// ReconcileOrder is for trusted registry mutations, never for accepting a patch.
func ReconcileOrder(r *Registry, old Order) Order {
	order := DefaultOrder(r)
	if ValidateFamilies(old.Families) == nil {
		order.Families = append([]string{}, old.Families...)
	}
	ids := map[string]string{}
	for _, c := range r.Connections {
		ids[c.ID] = c.Family
	}
	for _, family := range Families {
		list := []string{}
		seen := map[string]bool{}
		for _, id := range old.Connections[family] {
			if ids[id] == family && !seen[id] {
				list = append(list, id)
				seen[id] = true
			}
		}
		for _, id := range order.Connections[family] {
			if !seen[id] {
				list = append(list, id)
			}
		}
		order.Connections[family] = list
	}
	return order
}
func Candidates(r *Registry, selection Selection, order Order) ([]Connection, error) {
	if err := ValidateSelection(selection); err != nil {
		return nil, err
	}
	if err := ValidateOrder(r, order); err != nil {
		return nil, err
	}
	byID := map[string]Connection{}
	for _, c := range r.Connections {
		byID[c.ID] = c
	}
	result := []Connection{}
	if selection.Mode == "connection" {
		c, exists := byID[selection.ID]
		if !exists {
			return nil, fmt.Errorf("selected connection does not exist")
		}
		if c.Enabled {
			result = append(result, c.Clone())
		}
		return result, nil
	}
	for _, family := range order.Families {
		if selection.Mode == "transport" && selection.Family != family {
			continue
		}
		for _, id := range order.Connections[family] {
			if c := byID[id]; c.Enabled {
				result = append(result, c.Clone())
			}
		}
	}
	return result, nil
}
