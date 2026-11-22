package config

import (
	"encoding/json"
	"fmt"
	"github.com/MyHeartRaces/FLR/runtime/internal/dataplane"
	"github.com/MyHeartRaces/FLR/runtime/internal/lan"
	"github.com/MyHeartRaces/FLR/runtime/internal/native"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

type Profiles struct {
	AWG     map[string]string
	Tunnels map[string][]byte
}

func LoadProfiles(dir, wan string) (Profiles, error) {
	p := Profiles{AWG: map[string]string{}, Tunnels: map[string][]byte{}}
	b, e := os.ReadFile(filepath.Join(dir, "awg.conf"))
	if e != nil {
		return p, e
	}
	p.AWG, e = ParseAWG(b)
	if e != nil {
		return p, e
	}
	b, e = os.ReadFile(filepath.Join(dir, "sing-box-outbounds.json"))
	if e != nil {
		return p, e
	}
	var base struct {
		Outbounds []map[string]any `json:"outbounds"`
	}
	if e = json.Unmarshal(b, &base); e != nil {
		return p, e
	}
	for i, name := range []string{"gecko", "vless"} {
		wanted := []string{"hysteria2", "vless"}[i]
		var out map[string]any
		for _, v := range base.Outbounds {
			if v["type"] == wanted {
				out = v
				break
			}
		}
		if out == nil {
			return p, fmt.Errorf("missing %s outbound", name)
		}
		ip, _ := out["server"].(string)
		if a, e := netip.ParseAddr(ip); e != nil || !a.Is4() {
			return p, fmt.Errorf("transport endpoint must be IPv4")
		}
		out["bind_interface"] = wan
		out["routing_mark"] = uint32(0x80000000)
		dev := []string{"flr-hy", "flr-vless"}[i]
		cfg := map[string]any{"log": map[string]any{"level": "warn"}, "inbounds": []any{
			map[string]any{"type": "tun", "tag": "lan-tun", "interface_name": dev, "address": []string{[]string{SlotAddress, "198.18.0.5/30"}[i]}, "mtu": 1380, "auto_route": false, "stack": "system"},
			map[string]any{"type": "socks", "tag": "health", "listen": "127.0.0.1", "listen_port": 1081 + i},
		}, "outbounds": []any{out}, "route": map[string]any{"final": out["tag"]}}
		p.Tunnels[name], e = json.MarshalIndent(cfg, "", "  ")
		if e != nil {
			return p, e
		}
	}
	return p, nil
}
func uci(args ...string) error         { return dataplane.Run("uci", args...) }
func set(pkg, key, value string) error { return uci("set", pkg+"."+key+"="+value) }
func Backup(dir string) error {
	if !filepath.IsAbs(dir) {
		return fmt.Errorf("backup path must be absolute")
	}
	if e := os.MkdirAll(dir, 0700); e != nil {
		return e
	}
	for _, n := range []string{"network", "firewall", "dhcp"} {
		if _, e := os.Stat(filepath.Join(dir, n)); e == nil {
			continue
		}
		b, e := os.ReadFile("/etc/config/" + n)
		if e != nil {
			return e
		}
		if e = os.WriteFile(filepath.Join(dir, n), b, 0600); e != nil {
			return e
		}
	}
	return nil
}
func Prepare(dir, wan string) error {
	p, e := LoadProfiles(dir, wan)
	if e != nil {
		return e
	}
	if e = os.MkdirAll("/etc/flr-runtime", 0700); e != nil {
		return e
	}
	awgRaw, e := os.ReadFile(filepath.Join(dir, "awg.conf"))
	if e != nil {
		return e
	}
	if e = SaveAWG("/etc/flr-runtime/primary-awg.conf", awgRaw); e != nil {
		return e
	}
	for n, b := range p.Tunnels {
		path := "/etc/flr-runtime/" + n + ".json"
		if e = os.WriteFile(path, b, 0600); e != nil {
			return e
		}
		if e = dataplane.Run("sing-box", "check", "-c", path); e != nil {
			return fmt.Errorf("%s configuration rejected", n)
		}
	}
	if e = configureAWG(p.AWG); e != nil {
		return e
	}
	if e = configureFirewall(); e != nil {
		return e
	}
	for _, k := range []string{"flow_offloading", "flow_offloading_hw"} {
		if e = set("firewall", "@defaults[0]."+k, "0"); e != nil {
			return e
		}
	}
	for _, pkg := range []string{"network", "firewall"} {
		if e = uci("commit", pkg); e != nil {
			return e
		}
	}
	if e = dataplane.Run("ubus", "call", "network", "reload"); e != nil {
		return e
	}
	if e = dataplane.Run("/etc/init.d/firewall", "restart"); e != nil {
		return e
	}
	return MigrateSlot()
}

func ValidateBackup(dir string) error { return dataplane.ValidateBackup(dir) }

// routerLAN returns the live LAN address for DHCP option 6. A guessed address
// would hand clients a DNS server that does not exist, so no fallback is used.
func routerLAN() (lan.LAN, error) {
	l, e := lan.Discover(lan.Interface)
	if e == nil {
		return l, nil
	}
	ip, e1 := native.Output("uci", "-q", "get", "network.lan.ipaddr")
	mask, e2 := native.Output("uci", "-q", "get", "network.lan.netmask")
	if e1 == nil && (e2 == nil || strings.Contains(string(ip), "/")) {
		if u, err := lan.ParseUCI(string(ip), string(mask)); err == nil {
			return u, nil
		}
	}
	return lan.LAN{}, fmt.Errorf("cannot determine router LAN address for DHCP DNS: %w", e)
}

func HomeSetup(guard string) error {
	router, e := routerLAN()
	if e != nil {
		return e
	}
	return homeSetup(guard, router)
}

func homeSetup(guard string, router lan.LAN) error {
	var e error
	if e := os.WriteFile("/etc/flr-runtime/boot-guard.nft", []byte(guard), 0600); e != nil {
		return e
	}
	for k, v := range map[string]string{"flr_guard": "include", "flr_guard.type": "nftables", "flr_guard.path": "/etc/flr-runtime/boot-guard.nft", "flr_guard.position": "ruleset-post"} {
		if e = set("firewall", k, v); e != nil {
			return e
		}
	}
	if e = set("dhcp", "@dnsmasq[0].port", policyDNSMasqPort); e != nil {
		return e
	}
	if e = set("dhcp", "@dnsmasq[0].noresolv", "1"); e != nil {
		return e
	}
	if e = uci("-q", "delete", "dhcp.@dnsmasq[0].server"); e != nil && !native.Exit(e, 1) {
		return e
	}
	old, e := native.Output("uci", "-q", "get", "dhcp.lan.dhcp_option")
	if e != nil && !native.Exit(e, 1) {
		return e
	}
	if e = uci("-q", "delete", "dhcp.lan.dhcp_option"); e != nil && !native.Exit(e, 1) {
		return e
	}
	for _, option := range strings.Fields(string(old)) {
		if !strings.HasPrefix(option, "6,") {
			if e = uci("add_list", "dhcp.lan.dhcp_option="+option); e != nil {
				return e
			}
		}
	}
	if e = uci("add_list", "dhcp.lan.dhcp_option=6,"+router.Addr.String()); e != nil {
		return e
	}
	for _, pkg := range []string{"firewall", "dhcp"} {
		if e = uci("commit", pkg); e != nil {
			return e
		}
	}
	if e = dataplane.Run("fw4", "check"); e != nil {
		return e
	}
	if e = dataplane.Run("/etc/init.d/firewall", "restart"); e != nil {
		return e
	}
	if e = dataplane.Run("/etc/init.d/dnsmasq", "restart"); e != nil {
		return e
	}
	return nil
}

func Home(guard string) error {
	if e := HomeSetup(guard); e != nil {
		return e
	}
	if e := dataplane.Run("/etc/init.d/flr-runtime", "enable"); e != nil {
		return e
	}
	return dataplane.Run("/etc/init.d/flr-runtime", "restart")
}

func configureAWG(awg map[string]string) error {
	return configureAWGWith(awg, dataplane.Run)
}

func configureAWGWith(awg map[string]string, run func(string, ...string) error) error {
	uci := func(args ...string) error { return run("uci", args...) }
	set := func(pkg, key, value string) error { return uci("set", pkg+"."+key+"="+value) }
	var e error
	_, _ = os.Stat("/etc/config/network")
	if e = set("network", "flr_awg", "interface"); e != nil {
		return e
	}
	vals := map[string]string{"proto": "amneziawg", "private_key": awg["PrivateKey"], "mtu": awgMTU(awg), "fwmark": "0x80000000", "tunlink": "wan"}
	for k, v := range vals {
		if e = set("network", "flr_awg."+k, v); e != nil {
			return e
		}
	}
	if e = uci("-q", "delete", "network.flr_awg.addresses"); e != nil && !native.Exit(e, 1) {
		return e
	}
	if e = uci("add_list", "network.flr_awg.addresses="+awg["Address"]); e != nil {
		return e
	}
	fields := awgUCIFields
	for field, key := range fields {
		v := awg[field]
		if v == "" {
			if e = uci("-q", "delete", "network.flr_awg.awg_"+key); e != nil && !native.Exit(e, 1) {
				return e
			}
			continue
		}
		if v == "true" || v == "on" {
			v = "1"
		}
		if v == "false" || v == "off" {
			v = "0"
		}
		if e = set("network", "flr_awg.awg_"+key, v); e != nil {
			return e
		}
	}
	endpoint, _ := netip.ParseAddrPort(awg["Endpoint"])
	if e = set("network", "flr_peer", "amneziawg_flr_awg"); e != nil {
		return e
	}
	for k, v := range map[string]string{"public_key": awg["PublicKey"], "preshared_key": awg["PresharedKey"], "endpoint_host": endpoint.Addr().String(), "endpoint_port": strconv.Itoa(int(endpoint.Port())), "persistent_keepalive": awgKeepalive(awg), "route_allowed_ips": "0"} {
		if e = set("network", "flr_peer."+k, v); e != nil {
			return e
		}
	}
	if e = uci("-q", "delete", "network.flr_peer.allowed_ips"); e != nil && !native.Exit(e, 1) {
		return e
	}
	if e = uci("add_list", "network.flr_peer.allowed_ips=0.0.0.0/0"); e != nil {
		return e
	}
	return nil
}

func configureFirewall() error {
	var e error
	for _, key := range []string{"flow_offloading", "flow_offloading_hw"} {
		if e = set("firewall", "@defaults[0]."+key, "0"); e != nil {
			return e
		}
	}
	if e = set("firewall", "flr_zone", "zone"); e != nil {
		return e
	}
	for k, v := range map[string]string{"name": "flr", "input": "REJECT", "output": "ACCEPT", "forward": "REJECT", "mtu_fix": "1"} {
		if e = set("firewall", "flr_zone."+k, v); e != nil {
			return e
		}
	}
	if e = uci("-q", "delete", "firewall.flr_zone.device"); e != nil && !native.Exit(e, 1) {
		return e
	}
	for _, dev := range []string{"flr_awg", "flr-hy", "flr-vless"} {
		if e = uci("add_list", "firewall.flr_zone.device="+dev); e != nil {
			return e
		}
	}
	if e = set("firewall", "flr_forward", "forwarding"); e != nil {
		return e
	}
	if e = set("firewall", "flr_forward.src", "lan"); e != nil {
		return e
	}
	if e = set("firewall", "flr_forward.dest", "flr"); e != nil {
		return e
	}
	return nil
}

func awgMTU(awg map[string]string) string {
	if awg["MTU"] != "" {
		return awg["MTU"]
	}
	return "1380"
}
func awgKeepalive(awg map[string]string) string {
	if awg["PersistentKeepalive"] != "" {
		return awg["PersistentKeepalive"]
	}
	return "25"
}
