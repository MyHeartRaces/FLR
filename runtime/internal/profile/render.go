package profile

import (
	"encoding/json"
	"fmt"
	"net"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// Rendered contains private generated configs and argv (never shell commands).
// For wstunnel, BindInterface/OuterEndpoints require the process manager to pin
// the bearer address and ensure its WAN route: upstream has SO_MARK but no
// SO_BINDTODEVICE CLI. Args do not include the executable.
type Rendered struct {
	SingBox        []byte
	Xray           []byte
	Sidecar        []byte
	SingBoxArgs    []string
	XrayArgs       []string
	SidecarArgs    []string
	Capabilities   Capabilities
	BindInterface  string
	OuterEndpoints []string
}

// Render does not execute engines or write files. The caller owns private file
// creation, missing-component gating, endpoint pinning and process lifecycle.
func Render(p Profile, wan, runtimeDir string) (Rendered, error) {
	if !interfacePattern.MatchString(wan) || !filepath.IsAbs(runtimeDir) || filepath.Clean(runtimeDir) != runtimeDir || strings.ContainsRune(runtimeDir, 0) {
		return Rendered{}, fmt.Errorf("invalid render context")
	}
	if e := validateProfile(p); e != nil {
		return Rendered{}, e
	}
	cfg := map[string]any{"log": map[string]any{"level": "warn"}, "inbounds": []any{
		map[string]any{"type": "tun", "tag": "lan-tun", "interface_name": "flr-hy", "address": []string{"198.18.0.1/30"}, "mtu": 1380, "auto_route": false, "stack": "system"},
		map[string]any{"type": "socks", "tag": "health", "listen": "127.0.0.1", "listen_port": 1081},
	}, "route": map[string]any{"final": "proxy"}}
	result := Rendered{Capabilities: p.Capabilities, BindInterface: wan, SingBoxArgs: []string{"run", "-c", filepath.Join(runtimeDir, "proxy-sing-box.json")}}
	route := object(cfg["route"])
	switch p.Engine {
	case "sing-box":
		outbound := clone(p.Outbound)
		outbound["tag"] = "proxy"
		outbounds := []any{outbound}
		bearer := outbound
		if p.Detour != nil {
			detour := clone(p.Detour)
			detour["tag"] = "shadowtls"
			detour["bind_interface"] = wan
			detour["routing_mark"] = uint32(0x80000000)
			outbounds = append(outbounds, detour)
			// The manager pins and routes the socket that actually leaves the router.
			// The inner Shadowsocks destination remains its independent protocol input.
			bearer = detour
		} else {
			outbound["bind_interface"] = wan
			outbound["routing_mark"] = uint32(0x80000000)
		}
		cfg["outbounds"] = outbounds
		result.OuterEndpoints = []string{
			net.JoinHostPort(str(bearer, "server"), strconv.Itoa(number(bearer, "server_port", 443))),
		}

	case "xray":
		o := clone(p.Outbound)
		o["tag"] = "proxy"
		stream := object(o["streamSettings"])
		if str(stream, "network") == "ws" {
			w, e := nativeXrayWS(object(stream["wsSettings"]))
			if e != nil {
				return Rendered{}, e
			}
			stream["wsSettings"] = w
		}
		// Xray SocketConfig.Mark is int32; preserve SO_MARK bits in signed JSON.
		stream["sockopt"] = map[string]any{"mark": int32(-2147483648), "interface": wan, "domainStrategy": "UseIPv4"}
		x := map[string]any{"log": map[string]any{"loglevel": "warning"}, "inbounds": []any{map[string]any{"tag": "flr-sidecar", "listen": "127.0.0.1", "port": 1083, "protocol": "socks", "settings": map[string]any{"auth": "noauth", "udp": true}}}, "outbounds": []any{o}}
		b, e := json.Marshal(x)
		if e != nil {
			return Rendered{}, fmt.Errorf("cannot render Xray")
		}
		result.Xray = b
		result.XrayArgs = []string{"run", "-config", filepath.Join(runtimeDir, "proxy-xray.json")}
		cfg["outbounds"] = []any{map[string]any{"type": "socks", "tag": "proxy", "server": "127.0.0.1", "server_port": 1083, "version": "5"}}
		v := object(array(object(o["settings"])["vnext"])[0])
		result.OuterEndpoints = []string{net.JoinHostPort(str(v, "address"), strconv.Itoa(number(v, "port", 443)))}
	case "wstunnel":
		w := p.WGWS
		ep := clone(w.Endpoint)
		ep["tag"] = "proxy"
		ep["system"] = false
		ep["detour"] = "wg-loopback"
		peer := object(array(ep["peers"])[0])
		peer["address"] = "127.0.0.1"
		peer["port"] = 51821
		cfg["endpoints"] = []any{ep}
		cfg["outbounds"] = []any{map[string]any{"type": "direct", "tag": "wg-loopback", "inet4_bind_address": "127.0.0.1"}}
		ws := w.Websocket
		args := []string{"--log-lvl", "WARN", "--no-color", "client", "--socket-so-mark", "2147483648", "--tls-verify-certificate", "--websocket-ping-frequency", "15s", "--http-upgrade-path-prefix", strings.TrimPrefix(str(ws, "path"), "/")}
		sni := str(ws, "sni")
		if sni == "" {
			sni = str(ws, "server")
		}
		if net.ParseIP(sni) == nil {
			args = append(args, "--tls-sni-override", sni)
		}
		h, e := wgwsHeaders(ws)
		if e != nil {
			return Rendered{}, e
		}
		names := []string{}
		for k := range h {
			names = append(names, k)
		}
		sort.Strings(names)
		for _, k := range names {
			args = append(args, "-H", k+": "+str(h, k))
		}
		endpoint := net.JoinHostPort(str(ws, "server"), strconv.Itoa(number(ws, "server_port", 443)))
		args = append(args, "-L", "udp://127.0.0.1:51821:"+w.RemoteUDP+"?timeout_sec=0", "wss://"+endpoint)
		result.SidecarArgs = args
		result.OuterEndpoints = []string{endpoint}
		b, e := json.Marshal(map[string]any{"websocket": ws, "local_udp_listen": "127.0.0.1:51821", "remote_udp_endpoint": w.RemoteUDP, "wan_interface": wan, "routing_mark": uint32(0x80000000)})
		if e != nil {
			return Rendered{}, fmt.Errorf("cannot render WGWS sidecar")
		}
		result.Sidecar = b
	default:
		return Rendered{}, fmt.Errorf("unsupported render engine")
	}
	if !p.Capabilities.UDP {
		route["rules"] = []any{map[string]any{"network": "udp", "action": "reject"}}
	}
	b, e := json.Marshal(cfg)
	if e != nil {
		return Rendered{}, fmt.Errorf("cannot render sing-box")
	}
	result.SingBox = b
	return result, nil
}
