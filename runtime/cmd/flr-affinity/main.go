// flr-affinity exports production recipes for isolated CI qualification only.
package main

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"os"

	"github.com/MyHeartRaces/FLR/runtime/internal/contract"
	"github.com/MyHeartRaces/FLR/runtime/internal/dataplane"
	"github.com/MyHeartRaces/FLR/runtime/internal/policy"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: flr-affinity POLICY")
		os.Exit(2)
	}
	if err := run(os.Args[1]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
func run(dir string) error {
	p, err := policy.Load(dir)
	if err != nil {
		return err
	}
	proxy := contract.Selection{General: contract.Gecko, Games: contract.Gecko}
	b, err := dataplane.Build(p, dataplane.Options{LAN: "br-lan", WAN: "eth1", Selection: proxy, Profiles: map[string]contract.Class{"192.168.8.2": contract.General}})
	if err != nil {
		return err
	}
	anchor, err := dataplane.Build(p, dataplane.Options{
		LAN: "br-lan", WAN: "eth1", Continuity: true, Replace: true,
		Selection: contract.Selection{General: contract.Continuity, Games: contract.Continuity},
	})
	if err != nil {
		return err
	}
	recovered, err := dataplane.SelectionBatch(contract.Selection{General: contract.AWG, Games: contract.AWG}, false)
	if err != nil {
		return err
	}
	failed, err := dataplane.SelectionBatch(proxy, false)
	if err != nil {
		return err
	}
	down, err := dataplane.SelectionBatch(contract.Selection{General: contract.Down, Games: contract.Down}, false)
	if err != nil {
		return err
	}
	rules := policy.EmptyCustomRules()
	// The harness makes this documentation address routable in its fixture.
	rules.Rules = []policy.CustomRule{{ID: "affinity-vpn", Type: policy.RuleIP, Value: "198.51.100.42", Mode: policy.RuleVPN, Enabled: true}}
	if err = rules.Normalize(netip.Prefix{}); err != nil {
		return err
	}
	configured := p.WithCustom(rules)
	tunnel := dataplane.StaticSetsBatch(configured.ForMode(policy.ModeTunnel))
	direct := dataplane.StaticSetsBatch(configured.ForMode(policy.ModeDirect))
	return json.NewEncoder(os.Stdout).Encode(map[string]any{
		"initial": b.Nft, "recovered": recovered, "failed": failed, "tunnel": tunnel, "direct": direct, "down": down,
		"routes": b.Routes, "rules": b.Rules,
		"anchor": map[string]any{"nft": anchor.Nft, "routes": anchor.Routes, "rules": anchor.Rules},
	})
}
