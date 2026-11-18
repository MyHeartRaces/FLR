package profile

import "sort"

// Candidates exhaust HY2, primary server group first, before advancing families.
// Lower numeric priority wins within a group/family; ID breaks ties.
func (r *Registry) Candidates(primaryGroup string) []Profile {
	result := []Profile{}
	for _, p := range r.Profiles {
		if p.Enabled && !p.UserDisabled && p.DisabledReason == "" {
			copy := p
			copy.Outbound = clone(p.Outbound)
			copy.Detour = clone(p.Detour)
			if p.WGWS != nil {
				w := *p.WGWS
				w.Websocket = clone(w.Websocket)
				w.Endpoint = clone(w.Endpoint)
				copy.WGWS = &w
			}
			result = append(result, copy)
		}
	}
	order := map[string]int{"hy2": 0}
	families := append(append([]string{}, r.FamilyOrder...), "reality", "vless", "ss2022", "wgws")
	rank := 1
	for _, family := range families {
		if _, exists := order[family]; !exists && family != "hy2" {
			order[family] = rank
			rank++
		}
	}
	sort.Slice(result, func(i, j int) bool {
		a, b := result[i], result[j]
		if order[a.Family] != order[b.Family] {
			return order[a.Family] < order[b.Family]
		}
		if a.Family == "hy2" && primaryGroup != "" {
			ap, bp := a.ServerGroup == primaryGroup, b.ServerGroup == primaryGroup
			if ap != bp {
				return ap
			}
		}
		if a.Priority != b.Priority {
			return a.Priority < b.Priority
		}
		return a.ID < b.ID
	})
	return result
}
