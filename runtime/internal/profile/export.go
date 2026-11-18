package profile

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
)

// Export formats. URL is a share link; JSON is a native outbound or wrapper
// object for options a link cannot carry.
const (
	ExportURL  = "url"
	ExportJSON = "json"
)

// Exported is a re-importable private configuration. It contains credentials:
// return it only through write-authorized operations and never log it.
type Exported struct {
	Format string `json:"format"`
	Engine string `json:"engine"`
	Config string `json:"config"`
	Note   string `json:"note,omitempty"`
}

// Export renders p so that Parse returns a profile with the same identity
// (engine, outbound, detour and WGWS payload). A share URL is preferred; when
// the URL importer cannot reproduce the stored payload exactly, the native
// JSON object accepted by Parse is returned instead. Both are verified by a
// round trip, so an export never silently drops an option.
func Export(p Profile) (Exported, error) {
	if e := validateProfile(p); e != nil {
		return Exported{}, fmt.Errorf("stored profile cannot be exported")
	}
	want, e := finish(Profile{Family: p.Family, Engine: p.Engine, Outbound: p.Outbound, Detour: p.Detour, WGWS: p.WGWS})
	if e != nil {
		return Exported{}, e
	}
	if link, ok := exportURL(p); ok && sameIdentity(link, want.ID) {
		return Exported{Format: ExportURL, Engine: p.Engine, Config: link}, nil
	}
	raw, e := exportJSON(p)
	if e != nil || !sameIdentity(raw, want.ID) {
		return Exported{}, fmt.Errorf("stored profile cannot be exported losslessly")
	}
	note := "sing-box outbound JSON: a share URL cannot carry every option of this profile"
	switch {
	case p.Engine == "xray":
		note = "Xray outbound JSON: a share URL cannot carry every option of this profile"
	case p.Detour != nil:
		note = "sing-box outbounds JSON with the ShadowTLS detour: a share URL cannot carry every option of this profile"
	}
	return Exported{Format: ExportJSON, Engine: p.Engine, Config: raw, Note: note}, nil
}

func sameIdentity(text, id string) bool {
	parsed, e := Parse([]byte(text))
	return e == nil && len(parsed) == 1 && parsed[0].ID == id
}

func exportJSON(p Profile) (string, error) {
	var value any
	switch {
	case p.WGWS != nil:
		value = wgwsWrapper(p.WGWS)
	case p.Detour != nil:
		outbound, detour := clone(p.Outbound), clone(p.Detour)
		outbound["tag"], outbound["detour"] = "proxy", "shadowtls"
		detour["tag"] = "shadowtls"
		value = map[string]any{"outbounds": []any{outbound, detour}}
	default:
		outbound := clone(p.Outbound)
		outbound["tag"] = "proxy"
		value = outbound
	}
	raw, e := json.MarshalIndent(value, "", "  ")
	if e != nil {
		return "", fmt.Errorf("cannot encode exported profile")
	}
	return string(raw), nil
}

// wgwsWrapper is the native Tracegate WGWS client document parseWGWS accepts.
func wgwsWrapper(w *WGWS) map[string]any {
	endpoint := clone(w.Endpoint)
	port := 51820
	if remote, e := net.ResolveUDPAddr("udp4", w.RemoteUDP); e == nil && remote.Port > 0 {
		port = remote.Port
	}
	peers := array(endpoint["peers"])
	if len(peers) == 1 {
		peer := object(peers[0])
		peer["address"], peer["port"] = "127.0.0.1", port
	}
	return map[string]any{
		"type":      "wgws",
		"schema":    "tracegate.wgws-client.v1",
		"websocket": clone(w.Websocket),
		"wstunnel":  map[string]any{"mode": "wireguard-over-websocket", "remote_udp_endpoint": w.RemoteUDP},
		"singbox":   map[string]any{"endpoints": []any{endpoint}},
	}
}

func exportURL(p Profile) (string, bool) {
	switch {
	case p.WGWS != nil:
		raw, e := json.Marshal(wgwsWrapper(p.WGWS))
		if e != nil {
			return "", false
		}
		return "wgws://" + base64.RawURLEncoding.EncodeToString(raw), true
	case p.Engine == "xray":
		return xrayURL(p.Outbound)
	case str(p.Outbound, "type") == "hysteria2":
		return hysteria2URL(p.Outbound)
	case str(p.Outbound, "type") == "vless":
		return vlessURL(p.Outbound)
	case str(p.Outbound, "type") == "shadowsocks":
		return shadowsocksURL(p.Outbound, p.Detour)
	}
	return "", false
}

// shareURL keeps the query order stable so repeated exports are identical.
func shareURL(scheme string, user *url.Userinfo, host string, port int, query [][2]string) string {
	parts := make([]string, 0, len(query))
	for _, kv := range query {
		parts = append(parts, url.QueryEscape(kv[0])+"="+url.QueryEscape(kv[1]))
	}
	u := url.URL{Scheme: scheme, User: user, Host: net.JoinHostPort(host, strconv.Itoa(port)), Path: "/", RawQuery: strings.Join(parts, "&")}
	return u.String()
}
func joinStrings(v any) string {
	items := []string{}
	for _, item := range array(v) {
		s, _ := item.(string)
		items = append(items, s)
	}
	return strings.Join(items, ",")
}

func hysteria2URL(o map[string]any) (string, bool) {
	obfs, tls := object(o["obfs"]), object(o["tls"])
	query := [][2]string{{"obfs", str(obfs, "type")}, {"obfs-password", str(obfs, "password")}}
	if str(obfs, "type") == "gecko" {
		query = append(query, [2]string{"obfs-min-packet-size", strconv.Itoa(number(obfs, "min_packet_size", 512))}, [2]string{"obfs-max-packet-size", strconv.Itoa(number(obfs, "max_packet_size", 1200))})
	}
	query = append(query, [2]string{"sni", str(tls, "server_name")})
	if tls["alpn"] != nil {
		query = append(query, [2]string{"alpn", joinStrings(tls["alpn"])})
	}
	if ports := array(o["server_ports"]); len(ports) > 0 {
		ranges := []string{}
		for _, r := range ports {
			s, _ := r.(string)
			ranges = append(ranges, strings.ReplaceAll(s, ":", "-"))
		}
		query = append(query, [2]string{"mport", strings.Join(ranges, ",")})
	}
	if hop, ok := o["hop_interval"].(string); ok {
		seconds := strings.TrimSuffix(hop, "s")
		if n, e := strconv.Atoi(seconds); e != nil || n < 1 || strconv.Itoa(n)+"s" != hop {
			return "", false
		}
		query = append(query, [2]string{"hop-interval", seconds})
	}
	return shareURL("hysteria2", url.User(str(o, "password")), str(o, "server"), number(o, "server_port", 443), query), true
}

func vlessURL(o map[string]any) (string, bool) {
	tls := object(o["tls"])
	utls, reality := object(tls["utls"]), object(tls["reality"])
	query := [][2]string{{"encryption", "none"}}
	if reality != nil {
		query = append(query, [2]string{"security", "reality"}, [2]string{"pbk", str(reality, "public_key")}, [2]string{"sid", str(reality, "short_id")})
	} else {
		query = append(query, [2]string{"security", "tls"})
		if tls["alpn"] != nil {
			query = append(query, [2]string{"alpn", joinStrings(tls["alpn"])})
		}
	}
	query = append(query, [2]string{"sni", str(tls, "server_name")}, [2]string{"fp", str(utls, "fingerprint")})
	if flow := str(o, "flow"); flow != "" {
		query = append(query, [2]string{"flow", flow})
	}
	transport := object(o["transport"])
	switch str(transport, "type") {
	case "":
		query = append(query, [2]string{"type", "tcp"})
	case "ws":
		query = append(query, [2]string{"type", "ws"}, [2]string{"path", str(transport, "path")})
		if host := str(object(transport["headers"]), "Host"); host != "" {
			query = append(query, [2]string{"host", host})
		}
	case "grpc":
		query = append(query, [2]string{"type", "grpc"}, [2]string{"serviceName", str(transport, "service_name")}, [2]string{"mode", "gun"})
	default:
		return "", false
	}
	return shareURL("vless", url.User(str(o, "uuid")), str(o, "server"), number(o, "server_port", 443), query), true
}

// xrayURL covers the XHTTP/SplitHTTP outbounds the URI importer keeps on Xray.
func xrayURL(o map[string]any) (string, bool) {
	stream := object(o["streamSettings"])
	network := str(stream, "network")
	if network != "xhttp" && network != "splithttp" {
		return "", false
	}
	vnext := array(object(o["settings"])["vnext"])
	if len(vnext) != 1 {
		return "", false
	}
	server := object(vnext[0])
	users := array(server["users"])
	if len(users) != 1 {
		return "", false
	}
	user := object(users[0])
	query := [][2]string{{"encryption", str(user, "encryption")}, {"security", str(stream, "security")}}
	switch str(stream, "security") {
	case "reality":
		r := object(stream["realitySettings"])
		query = append(query, [2]string{"pbk", str(r, "publicKey")}, [2]string{"sid", str(r, "shortId")}, [2]string{"spx", str(r, "spiderX")}, [2]string{"sni", str(r, "serverName")}, [2]string{"fp", str(r, "fingerprint")})
	case "tls":
		t := object(stream["tlsSettings"])
		query = append(query, [2]string{"sni", str(t, "serverName")}, [2]string{"fp", str(t, "fingerprint")})
		if t["alpn"] != nil {
			query = append(query, [2]string{"alpn", joinStrings(t["alpn"])})
		}
	default:
		return "", false
	}
	if flow := str(user, "flow"); flow != "" {
		query = append(query, [2]string{"flow", flow})
	}
	x := object(stream["xhttpSettings"])
	query = append(query, [2]string{"type", network}, [2]string{"path", str(x, "path")}, [2]string{"mode", str(x, "mode")})
	if host := str(x, "host"); host != "" {
		query = append(query, [2]string{"host", host})
	}
	return shareURL("vless", url.User(str(user, "id")), str(server, "address"), number(server, "port", 443), query), true
}

// shadowsocksURL emits SIP002 with the shadow-tls plugin string the importer
// reads (host, password, version). It only applies when the ShadowTLS bearer
// and the inner Shadowsocks destination are the same server and port.
func shadowsocksURL(o, detour map[string]any) (string, bool) {
	if detour == nil {
		return "", false
	}
	tls := object(detour["tls"])
	password := str(detour, "password")
	if strings.Contains(password, ";") || strings.Contains(str(tls, "server_name"), ";") {
		return "", false
	}
	credentials := base64.RawURLEncoding.EncodeToString([]byte(str(o, "method") + ":" + str(o, "password")))
	plugin := "shadow-tls;host=" + str(tls, "server_name") + ";password=" + password + ";version=" + strconv.Itoa(number(detour, "version", 3))
	return shareURL("ss", url.User(credentials), str(detour, "server"), number(detour, "server_port", 443), [][2]string{{"plugin", plugin}}), true
}
