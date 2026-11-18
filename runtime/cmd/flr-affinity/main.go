// flr-affinity exports production recipes for isolated CI qualification only.
package main

import (
	"encoding/json"
	"fmt"
	"github.com/MyHeartRaces/FLR/runtime/internal/contract"
	"github.com/MyHeartRaces/FLR/runtime/internal/dataplane"
	"github.com/MyHeartRaces/FLR/runtime/internal/policy"
	"os"
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
	recovered, err := dataplane.SelectionBatch(contract.Selection{General: contract.AWG, Games: contract.AWG}, false)
	if err != nil {
		return err
	}
	failed, err := dataplane.SelectionBatch(proxy, false)
	if err != nil {
		return err
	}
	return json.NewEncoder(os.Stdout).Encode(map[string]any{"initial": b.Nft, "recovered": recovered, "failed": failed, "routes": b.Routes, "rules": b.Rules})
}
