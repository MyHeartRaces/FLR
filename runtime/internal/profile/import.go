package profile

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/MyHeartRaces/FLR/runtime/internal/validation"
	"io"
	"net"
	"net/netip"
	"net/url"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Parse accepts one bounded JSON/URI/subscription batch. No partial result is
// returned on any error. It never fetches URLs or stores subscription sources.
func Parse(data []byte) ([]Profile, error) {
	if len(data) == 0 || len(data) > MaxImportBytes {
		return nil, fmt.Errorf("import must contain 1..1048576 bytes")
	}
	p, e := parseData(bytes.TrimSpace(data), 0)
	if e != nil {
		return nil, e
	}
	if len(p) == 0 || len(p) > MaxProfiles {
		return nil, fmt.Errorf("import requires 1..64 profiles")
	}
	seen := map[string]bool{}
	for index, v := range p {
		if seen[v.ID] {
			return nil, validation.At(fmt.Errorf("duplicate profile identity"), index+1)
		}
		seen[v.ID] = true
	}
	return p, nil
}
func parseData(data []byte, depth int) ([]Profile, error) {
	if depth > 3 || len(data) == 0 {
		return nil, fmt.Errorf("invalid import nesting")
	}
	if data[0] == '{' || data[0] == '[' {
		v, e := decodeJSON(data)
		if e != nil {
			return nil, e
		}
		if list, ok := v.([]any); ok {
			out := []Profile{}
			for index, item := range list {
				p, e := parseObject(object(item))
				if e != nil {
					return nil, validation.At(e, index+1)
				}
				out = append(out, p...)
				if len(out) > MaxProfiles {
					return nil, fmt.Errorf("profile limit exceeded")
				}
			}
			return out, nil
		}
		return parseObject(object(v))
	}
	text := string(data)
	if !strings.Contains(text, "://") {
		b, e := decode64(text)
		if e != nil {
			return nil, fmt.Errorf("unsupported import format")
		}
		return parseData(bytes.TrimSpace(b), depth+1)
	}
	result := []Profile{}
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		p, e := parseURI(line)
		if e != nil {
			return nil, validation.At(e, len(result)+1)
		}
		result = append(result, p)
		if len(result) > MaxProfiles {
			return nil, fmt.Errorf("profile limit exceeded")
		}
	}
	return result, nil
}
func decode64(s string) ([]byte, error) {
	s = strings.Map(func(r rune) rune {
		if r == ' ' || r == '\r' || r == '\n' || r == '\t' {
			return -1
		}
		return r
	}, s)
	for _, enc := range []*base64.Encoding{base64.RawURLEncoding, base64.URLEncoding, base64.RawStdEncoding, base64.StdEncoding} {
		b, e := enc.DecodeString(s)
		if e == nil {
			return b, nil
		}
	}
	return nil, fmt.Errorf("invalid base64 payload")
}

// Reject duplicate JSON object keys and excessive nesting before normalization.
func decodeJSON(data []byte) (any, error) {
	d := json.NewDecoder(bytes.NewReader(data))
	v, e := jsonValue(d, 0)
	if e != nil {
		return nil, fmt.Errorf("invalid JSON configuration")
	}
	if _, e = d.Token(); e != io.EOF {
		return nil, fmt.Errorf("trailing JSON data")
	}
	return v, nil
}
func jsonValue(d *json.Decoder, depth int) (any, error) {
	if depth > 32 {
		return nil, fmt.Errorf("JSON depth exceeded")
	}
	t, e := d.Token()
	if e != nil {
		return nil, e
	}
	switch delim := t.(type) {
	case json.Delim:
		switch delim {
		case '{':
			m := map[string]any{}
			for d.More() {
				k, e := d.Token()
				if e != nil {
					return nil, e
				}
				key, ok := k.(string)
				if !ok {
					return nil, fmt.Errorf("invalid key")
				}
				if _, ok = m[key]; ok {
					return nil, fmt.Errorf("duplicate key")
				}
				v, e := jsonValue(d, depth+1)
				if e != nil {
					return nil, e
				}
				m[key] = v
			}
			_, e = d.Token()
			return m, e
		case '[':
			a := []any{}
			for d.More() {
				v, e := jsonValue(d, depth+1)
				if e != nil {
					return nil, e
				}
				a = append(a, v)
			}
			_, e = d.Token()
			return a, e
		}
		return nil, fmt.Errorf("invalid delimiter")
	default:
		return t, nil
	}
}

func parseObject(m map[string]any) ([]Profile, error) {
	if m == nil {
		return nil, fmt.Errorf("profile must be a JSON object")
	}
	if schema := str(m, "schema"); strings.HasPrefix(schema, "tracegate.client-config-bundle.") {
		return parseBundle(m)
	}
	if str(m, "type") == "wgws" {
		p, e := parseWGWS(m)
		if e != nil {
			return nil, e
		}
		return []Profile{p}, nil
	}
	if str(m, "type") != "" {
		p, e := parseSingBoxOutbound(m, nil)
		if e != nil {
			return nil, e
		}
		return []Profile{p}, nil
	}
	if str(m, "protocol") != "" {
		p, e := parseXrayOutbound(m)
		if e != nil {
			return nil, e
		}
		return []Profile{p}, nil
	}
	if str(m, "proxy") != "" {
		if e := allowed(m, "proxy", "listen"); e != nil {
			return nil, e
		}
		link := str(m, "proxy")
		p, e := parseURI(link)
		if e != nil {
			return nil, e
		}
		return []Profile{p}, nil
	}
	if e := allowed(m, "log", "dns", "inbounds", "outbounds", "route", "routing", "remarks"); e != nil {
		return nil, e
	}
	outbounds := array(m["outbounds"])
	if len(outbounds) == 0 {
		return nil, fmt.Errorf("configuration has no supported outbounds")
	}
	result := []Profile{}
	used := map[string]bool{}
	for _, v := range outbounds {
		o := object(v)
		if o == nil {
			return nil, fmt.Errorf("invalid outbound")
		}
		tag := str(o, "tag")
		if tag != "" && used[tag] {
			return nil, fmt.Errorf("duplicate outbound tag")
		}
		used[tag] = true
	}
	detours := map[string]any{}
	for _, v := range outbounds {
		o := object(v)
		if str(o, "type") == "shadowtls" {
			detours[str(o, "tag")] = o
		}
	}
	consumed := map[string]bool{}
	for index, v := range outbounds {
		o := object(v)
		switch str(o, "type") {
		case "direct", "block":
			continue
		case "shadowtls":
			continue
		}
		switch str(o, "protocol") {
		case "freedom", "blackhole":
			continue
		}
		var p Profile
		var e error
		if str(o, "protocol") != "" {
			p, e = parseXrayOutbound(o)
		} else {
			p, e = parseSingBoxOutbound(o, object(detours[str(o, "detour")]))
		}
		if e != nil {
			return nil, validation.At(e, index+1)
		}
		if str(o, "detour") != "" {
			consumed[str(o, "detour")] = true
		}
		result = append(result, p)
	}
	for tag := range detours {
		if !consumed[tag] {
			return nil, fmt.Errorf("unreferenced ShadowTLS outbound")
		}
	}
	if len(result) == 0 {
		return nil, fmt.Errorf("configuration has no supported profiles")
	}
	return result, nil
}
func parseBundle(m map[string]any) ([]Profile, error) {
	if str(m, "schema") != "tracegate.client-config-bundle.v1" {
		return nil, fmt.Errorf("unsupported bundle schema")
	}
	if v, ok := m["version"]; ok {
		n, valid := integer(v)
		if !valid || n != 1 {
			return nil, fmt.Errorf("unsupported bundle version")
		}
	}
	rows := array(m["profiles"])
	if len(rows) == 0 || len(rows) > MaxProfiles || len(array(m["errors"])) > 0 {
		return nil, fmt.Errorf("invalid or incomplete bundle")
	}
	result := []Profile{}
	for index, row := range rows {
		record := object(row)
		start := len(result)
		for _, a := range array(record["artifacts"]) {
			artifact := object(a)
			filename := str(artifact, "filename")
			if filename != "" && (filepath.Base(filename) != filename || strings.ContainsAny(filename, "\\\x00") || filename == "." || filename == "..") {
				return nil, validation.At(fmt.Errorf("unsafe artifact filename"), index+1)
			}
			kind := str(artifact, "kind")
			if kind == "file" {
				continue
			}
			if kind != "sing-box-config" && kind != "xray-config" && kind != "wgws-config" {
				return nil, validation.At(fmt.Errorf("unsupported artifact kind"), index+1)
			}
			config := object(artifact["json"])
			if config == nil {
				raw, e := decode64(str(artifact, "contentBase64"))
				if e != nil {
					return nil, validation.At(fmt.Errorf("artifact JSON missing"), index+1)
				}
				v, e := decodeJSON(raw)
				if e != nil {
					return nil, validation.At(e, index+1)
				}
				config = object(v)
			}
			p, e := parseObject(config)
			if e != nil {
				return nil, validation.At(e, index+1)
			}
			result = append(result, p...)
		}
		if len(result) == start {
			found := false
			for _, l := range array(record["links"]) {
				link := str(object(l), "url")
				if strings.HasPrefix(link, "hy2://") || strings.HasPrefix(link, "hysteria2://") {
					p, e := parseURI(link)
					if e != nil {
						return nil, validation.At(e, index+1)
					}
					p, e = geckoBundleArtifact(p, array(record["artifacts"]))
					if e != nil {
						return nil, validation.At(e, index+1)
					}
					result = append(result, p)
					found = true
					break
				}
			}
			if !found {
				return nil, validation.At(fmt.Errorf("bundle profile lacks supported artifact"), index+1)
			}
		}
		meta := object(record["tracegate"])
		for _, source := range []map[string]any{meta, record} {
			if raw, exists := source["server_group"]; exists {
				if _, ok := raw.(string); !ok {
					return nil, validation.At(fmt.Errorf("invalid server group"), index+1)
				}
			}
		}
		group := str(meta, "server_group")
		if group == "" {
			group = str(record, "server_group")
		}
		if ValidateGroup(group) != nil {
			return nil, validation.At(fmt.Errorf("invalid server group"), index+1)
		}
		priority := 0
		if v, ok := record["priority"]; ok {
			n, valid := integer(v)
			if !valid || ValidatePriority(n) != nil {
				return nil, validation.At(fmt.Errorf("invalid priority"), index+1)
			}
			priority = n
		}
		for i := start; i < len(result); i++ {
			result[i].ServerGroup = group
			result[i].Priority = priority
		}
		if len(result) > MaxProfiles {
			return nil, validation.At(fmt.Errorf("profile limit exceeded"), index+1)
		}
	}
	return result, nil
}

func fieldTypes(m map[string]any, stringsKeys, boolKeys, intKeys []string) error {
	for _, k := range stringsKeys {
		if v, ok := m[k]; ok {
			value, valid := v.(string)
			if !valid || strings.ContainsRune(value, 0) {
				return fmt.Errorf("invalid string configuration field")
			}
		}
	}
	for _, k := range boolKeys {
		if v, ok := m[k]; ok {
			if _, valid := v.(bool); !valid {
				return fmt.Errorf("invalid boolean configuration field")
			}
		}
	}
	for _, k := range intKeys {
		if v, ok := m[k]; ok {
			n, valid := integer(v)
			if !valid || n < 0 {
				return fmt.Errorf("invalid numeric configuration field")
			}
		}
	}
	return nil
}

func validateTLS(tls map[string]any) error {
	if e := fieldTypes(tls, []string{"server_name"}, []string{"enabled", "insecure", "disable_sni"}, nil); e != nil {
		return e
	}
	if tls == nil || tls["enabled"] != true {
		return fmt.Errorf("verified TLS required")
	}
	if e := allowed(tls, "enabled", "server_name", "insecure", "alpn", "utls", "reality", "disable_sni"); e != nil {
		return e
	}
	if tls["insecure"] != nil && tls["insecure"] != false {
		return fmt.Errorf("insecure TLS is unsupported")
	}
	if tls["disable_sni"] != nil && tls["disable_sni"] != false {
		return fmt.Errorf("disabled SNI is unsupported")
	}
	if v, ok := tls["server_name"]; ok {
		if _, ok = v.(string); !ok {
			return fmt.Errorf("invalid TLS server name")
		}
	}
	if v, ok := tls["alpn"]; ok {
		if e := stringList(v); e != nil {
			return e
		}
	}
	if v, ok := tls["utls"]; ok {
		u := object(v)
		if u == nil {
			return fmt.Errorf("invalid uTLS")
		}
		if e := allowed(u, "enabled", "fingerprint"); e != nil {
			return e
		}
		if e := fieldTypes(u, []string{"fingerprint"}, []string{"enabled"}, nil); e != nil {
			return e
		}
		if _, ok := u["enabled"].(bool); !ok {
			return fmt.Errorf("invalid uTLS enabled")
		}
		if e := require(u, "fingerprint"); e != nil {
			return e
		}
	}
	if v, ok := tls["reality"]; ok {
		r := object(v)
		if r == nil || r["enabled"] != true {
			return fmt.Errorf("invalid REALITY")
		}
		if e := allowed(r, "enabled", "public_key", "short_id"); e != nil {
			return e
		}
		if e := fieldTypes(r, []string{"public_key", "short_id"}, []string{"enabled"}, nil); e != nil {
			return e
		}
		if e := require(r, "public_key"); e != nil {
			return e
		}
	}
	return nil
}
func stringList(v any) error {
	a, ok := v.([]any)
	if !ok || len(a) == 0 {
		return fmt.Errorf("invalid string list")
	}
	for _, s := range a {
		if v, ok := s.(string); !ok || v == "" {
			return fmt.Errorf("invalid string list")
		}
	}
	return nil
}
func headers(v any) error {
	m := object(v)
	if m == nil {
		return fmt.Errorf("invalid transport headers")
	}
	for k, v := range m {
		s, ok := v.(string)
		if !ok || len(k) > 128 || len(s) > 4096 || strings.ContainsAny(k+s, "\r\n\x00") {
			return fmt.Errorf("invalid transport header")
		}
	}
	return nil
}
func validateSingBox(o, detour map[string]any) (string, error) {
	typ := str(o, "type")
	common := []string{"type", "tag", "server", "server_port", "tls"}
	keys := append([]string{}, common...)
	family := ""
	switch typ {
	case "hysteria2":
		family = "hy2"
		keys = append(keys, "password", "obfs", "up_mbps", "down_mbps", "server_ports", "hop_interval", "hop_interval_max", "bbr_profile", "disable_chrome_parrot", "brutal_debug", "flr_random_sni_suffix")
	case "vless":
		family = "vless"
		keys = append(keys, "uuid", "flow", "packet_encoding", "transport")
	case "shadowsocks":
		family = "ss2022"
		keys = append(keys, "method", "password", "detour", "multiplex")
	default:
		return "", fmt.Errorf("unsupported sing-box outbound protocol")
	}
	if e := allowed(o, keys...); e != nil {
		return "", e
	}
	if e := fieldTypes(o, []string{"type", "tag", "server", "password", "username", "uuid", "flow", "packet_encoding", "detour", "method", "hop_interval", "hop_interval_max", "bbr_profile", "quic_congestion_control"}, []string{"quic", "brutal_debug", "disable_chrome_parrot"}, []string{"server_port", "up_mbps", "down_mbps"}); e != nil {
		return "", e
	}
	if e := hostPort(o, "server", "server_port"); e != nil {
		return "", e
	}
	if typ == "shadowsocks" && o["tls"] != nil {
		return "", fmt.Errorf("SS2022 TLS belongs on ShadowTLS detour")
	}
	if typ != "shadowsocks" {
		if e := validateTLS(object(o["tls"])); e != nil {
			return "", e
		}
	}
	switch typ {
	case "hysteria2":
		if _, present := o["flr_random_sni_suffix"]; present {
			if e := validateRandomSNI(o); e != nil {
				return "", e
			}
		}
		if e := require(o, "password"); e != nil {
			return "", e
		}
		obfs := object(o["obfs"])
		if obfs == nil {
			return "", fmt.Errorf("HY2 requires obfuscation")
		}
		if e := allowed(obfs, "type", "password", "min_packet_size", "max_packet_size"); e != nil {
			return "", e
		}
		if e := fieldTypes(obfs, []string{"type", "password"}, nil, []string{"min_packet_size", "max_packet_size"}); e != nil {
			return "", e
		}
		if e := require(obfs, "password"); e != nil {
			return "", e
		}
		switch str(obfs, "type") {
		case "gecko":
			for _, k := range []string{"min_packet_size", "max_packet_size"} {
				if v, ok := obfs[k]; ok {
					if _, valid := integer(v); !valid {
						return "", fmt.Errorf("invalid Gecko padding type")
					}
				}
			}
			min, max := number(obfs, "min_packet_size", 512), number(obfs, "max_packet_size", 1200)
			if min < 512 || max > 2048 || min > max {
				return "", fmt.Errorf("invalid Gecko padding band")
			}
			obfs["min_packet_size"] = min
			obfs["max_packet_size"] = max
		case "salamander":
			if obfs["min_packet_size"] != nil || obfs["max_packet_size"] != nil {
				return "", fmt.Errorf("Salamander cannot use Gecko padding")
			}
		default:
			return "", fmt.Errorf("unsupported HY2 obfuscation")
		}
		for _, k := range []string{"up_mbps", "down_mbps"} {
			if v, ok := o[k]; ok {
				n, valid := integer(v)
				if !valid || n < 1 {
					return "", fmt.Errorf("invalid bandwidth")
				}
			}
		}
		if v, ok := o["server_ports"]; ok {
			if e := validatePortRanges(v); e != nil {
				return "", e
			}
		}
		if v, ok := o["hop_interval"]; ok {
			if _, ok = v.(string); !ok {
				return "", fmt.Errorf("invalid hop interval")
			}
		}
		if e := validateHY2Options(o); e != nil {
			return "", e
		}
	case "vless":
		if e := require(o, "uuid"); e != nil {
			return "", e
		}
		if flow := str(o, "flow"); flow != "" && flow != "xtls-rprx-vision" {
			return "", fmt.Errorf("unsupported VLESS flow")
		}
		if v, ok := o["packet_encoding"]; ok && v != "xudp" && v != "packetaddr" {
			return "", fmt.Errorf("unsupported VLESS packet encoding")
		}
		if object(object(o["tls"])["reality"]) != nil {
			family = "reality"
		}
		if v, ok := o["transport"]; ok {
			tr := object(v)
			if e := fieldTypes(tr, []string{"type", "path", "method", "service_name", "idle_timeout", "ping_timeout", "early_data_header_name"}, []string{"permit_without_stream"}, []string{"max_early_data"}); e != nil {
				return "", e
			}
			switch str(tr, "type") {
			case "ws":
				if e := allowed(tr, "type", "path", "headers", "max_early_data", "early_data_header_name"); e != nil {
					return "", e
				}
				if v, ok := tr["headers"]; ok {
					if e := headers(v); e != nil {
						return "", e
					}
				}
			case "grpc":
				if e := allowed(tr, "type", "service_name", "idle_timeout", "ping_timeout", "permit_without_stream"); e != nil {
					return "", e
				}
			case "http":
				if e := allowed(tr, "type", "host", "path", "method", "headers"); e != nil {
					return "", e
				}
				if v, ok := tr["headers"]; ok {
					if e := headers(v); e != nil {
						return "", e
					}
				}
			default:
				return "", fmt.Errorf("unsupported VLESS transport")
			}
		}
	case "shadowsocks":
		if e := require(o, "method", "password", "detour"); e != nil {
			return "", e
		}
		switch str(o, "method") {
		case "2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm", "2022-blake3-chacha20-poly1305":
		default:
			return "", fmt.Errorf("SS2022 method required")
		}
		if detour == nil || str(detour, "type") != "shadowtls" {
			return "", fmt.Errorf("SS2022 requires ShadowTLS detour")
		}
		if e := allowed(detour, "type", "tag", "server", "server_port", "version", "password", "tls"); e != nil {
			return "", e
		}
		if e := fieldTypes(detour, []string{"type", "tag", "server", "password"}, nil, []string{"server_port", "version"}); e != nil {
			return "", e
		}
		if e := hostPort(detour, "server", "server_port"); e != nil {
			return "", e
		}
		if number(detour, "version", 0) != 3 {
			return "", fmt.Errorf("ShadowTLS v3 required")
		}
		if e := require(detour, "password"); e != nil {
			return "", e
		}
		if e := validateTLS(object(detour["tls"])); e != nil {
			return "", e
		}
		if v, ok := o["multiplex"]; ok {
			mux := object(v)
			if mux == nil {
				return "", fmt.Errorf("invalid multiplex settings")
			}
			if e := fieldTypes(mux, []string{"protocol"}, []string{"enabled", "padding"}, []string{"max_connections", "min_streams", "max_streams"}); e != nil {
				return "", e
			}
			if e := allowed(mux, "enabled", "protocol", "max_connections", "min_streams", "max_streams", "padding", "brutal"); e != nil {
				return "", e
			}
			if mux["brutal"] != nil {
				return "", fmt.Errorf("unsupported multiplex brutal settings")
			}
		}
	}
	return family, nil
}
func validatePortRanges(v any) error {
	if e := stringList(v); e != nil {
		return e
	}
	for _, r := range array(v) {
		s := r.(string)
		parts := strings.Split(s, ":")
		if len(parts) != 2 {
			return fmt.Errorf("invalid HY2 port range")
		}
		a, e := strconv.Atoi(parts[0])
		b, f := strconv.Atoi(parts[1])
		if e != nil || f != nil || a < 1 || b > 65535 || a > b {
			return fmt.Errorf("invalid HY2 port range")
		}
	}
	return nil
}
func parseSingBoxOutbound(input, detour map[string]any) (Profile, error) {
	o := clone(input)
	d := clone(detour)
	family, e := validateSingBox(o, d)
	if e != nil {
		return Profile{}, e
	}
	delete(o, "tag")
	if d != nil {
		delete(d, "tag")
		o["detour"] = "shadowtls"
	}
	return finish(Profile{Family: family, Engine: "sing-box", Outbound: o, Detour: d})
}

func validateXray(o map[string]any) (string, error) {
	if e := allowed(o, "protocol", "tag", "settings", "streamSettings"); e != nil {
		return "", e
	}
	if str(o, "protocol") != "vless" {
		return "", fmt.Errorf("unsupported Xray protocol")
	}
	settings := object(o["settings"])
	if settings == nil {
		return "", fmt.Errorf("Xray settings required")
	}
	if e := allowed(settings, "vnext"); e != nil {
		return "", e
	}
	next := array(settings["vnext"])
	if len(next) != 1 {
		return "", fmt.Errorf("Xray requires exactly one VLESS server")
	}
	v := object(next[0])
	if e := allowed(v, "address", "port", "users"); e != nil {
		return "", e
	}
	if e := hostPort(v, "address", "port"); e != nil {
		return "", e
	}
	users := array(v["users"])
	if len(users) != 1 {
		return "", fmt.Errorf("Xray requires exactly one VLESS user")
	}
	user := object(users[0])
	if e := fieldTypes(user, []string{"id", "encryption", "flow"}, nil, []string{"level"}); e != nil {
		return "", e
	}
	if e := allowed(user, "id", "encryption", "flow", "level"); e != nil {
		return "", e
	}
	if e := require(user, "id"); e != nil {
		return "", e
	}
	if str(user, "encryption") != "none" {
		return "", fmt.Errorf("unsupported VLESS encryption")
	}
	if flow := str(user, "flow"); flow != "" && flow != "xtls-rprx-vision" {
		return "", fmt.Errorf("unsupported VLESS flow")
	}
	stream := object(o["streamSettings"])
	if stream == nil {
		return "", fmt.Errorf("Xray stream settings required")
	}
	if e := allowed(stream, "network", "security", "tlsSettings", "realitySettings", "xhttpSettings", "wsSettings", "grpcSettings", "tcpSettings", "rawSettings"); e != nil {
		return "", e
	}
	family := "vless"
	switch str(stream, "security") {
	case "reality":
		family = "reality"
		r := object(stream["realitySettings"])
		if e := fieldTypes(r, []string{"serverName", "fingerprint", "publicKey", "password", "shortId", "spiderX"}, []string{"show"}, nil); e != nil {
			return "", e
		}
		if e := allowed(r, "serverName", "fingerprint", "publicKey", "password", "shortId", "spiderX", "show"); e != nil {
			return "", e
		}
		if e := require(r, "serverName", "fingerprint"); e != nil {
			return "", e
		}
		if str(r, "publicKey") == "" && str(r, "password") == "" {
			return "", fmt.Errorf("REALITY public key required")
		}
	case "tls":
		t := object(stream["tlsSettings"])
		if t == nil {
			return "", fmt.Errorf("TLS settings required")
		}
		if e := allowed(t, "serverName", "fingerprint", "alpn", "allowInsecure"); e != nil {
			return "", e
		}
		if t["allowInsecure"] != nil && t["allowInsecure"] != false {
			return "", fmt.Errorf("insecure TLS is unsupported")
		}
		if e := fieldTypes(t, []string{"serverName", "fingerprint"}, []string{"allowInsecure"}, nil); e != nil {
			return "", e
		}
		if v, ok := t["alpn"]; ok {
			if e := stringList(v); e != nil {
				return "", e
			}
		}
	default:
		return "", fmt.Errorf("verified Xray TLS/REALITY required")
	}
	network := str(stream, "network")
	if str(stream, "security") == "reality" {
		switch network {
		case "", "tcp", "raw", "xhttp", "splithttp", "grpc":
		default:
			return "", fmt.Errorf("Xray REALITY only supports RAW, XHTTP and gRPC")
		}
	}
	active := ""
	switch network {
	case "tcp", "raw", "":
		active = "rawSettings"
	case "xhttp", "splithttp":
		active = "xhttpSettings"
		x := object(stream[active])
		if e := fieldTypes(x, []string{"path", "host", "mode"}, nil, nil); e != nil {
			return "", e
		}
		if x == nil {
			return "", fmt.Errorf("XHTTP settings required")
		}
		if e := allowed(x, "path", "host", "mode", "headers", "extra"); e != nil {
			return "", e
		}
		mode := str(x, "mode")
		if mode != "" && mode != "auto" && mode != "packet-up" && mode != "stream-up" && mode != "stream-one" {
			return "", fmt.Errorf("unsupported XHTTP mode")
		}
		if v, ok := x["headers"]; ok {
			if e := headers(v); e != nil {
				return "", e
			}
		}
		if v, ok := x["extra"]; ok {
			extra := object(v)
			if extra == nil {
				return "", fmt.Errorf("invalid XHTTP extra")
			}
			if e := allowed(extra, "noGRPCHeader", "noSSEHeader", "xPaddingBytes", "scMaxEachPostBytes", "scMinPostsIntervalMs", "scMaxBufferedPosts", "scStreamUpServerSecs", "xmux"); e != nil {
				return "", e
			}
			for k, v := range extra {
				switch k {
				case "noGRPCHeader", "noSSEHeader":
					if _, ok := v.(bool); !ok {
						return "", fmt.Errorf("invalid XHTTP extra flag")
					}
				case "xmux":
					xm := object(v)
					if xm == nil {
						return "", fmt.Errorf("invalid XHTTP xmux")
					}
					if e := allowed(xm, "maxConcurrency", "maxConnections", "cMaxReuseTimes", "hMaxRequestTimes", "hMaxReusableSecs", "hKeepAlivePeriod"); e != nil {
						return "", e
					}
					for _, v := range xm {
						if !rangeValue(v) {
							return "", fmt.Errorf("invalid XHTTP xmux value")
						}
					}
				default:
					if !rangeValue(v) {
						return "", fmt.Errorf("invalid XHTTP extra value")
					}
				}
			}
		}
	case "ws":
		active = "wsSettings"
		w := object(stream[active])
		if e := fieldTypes(w, []string{"path", "earlyDataHeaderName"}, nil, []string{"maxEarlyData"}); e != nil {
			return "", e
		}
		if w == nil {
			return "", fmt.Errorf("WS settings required")
		}
		if e := allowed(w, "path", "headers", "maxEarlyData", "earlyDataHeaderName"); e != nil {
			return "", e
		}
		if v, ok := w["headers"]; ok {
			if e := headers(v); e != nil {
				return "", e
			}
		}
		if _, e := nativeXrayWS(w); e != nil {
			return "", e
		}
	case "grpc":
		active = "grpcSettings"
		g := object(stream[active])
		if e := fieldTypes(g, []string{"serviceName", "authority"}, []string{"multiMode", "permit_without_stream"}, []string{"idle_timeout", "health_check_timeout", "initial_windows_size"}); e != nil {
			return "", e
		}
		if g == nil {
			return "", fmt.Errorf("gRPC settings required")
		}
		if e := allowed(g, "serviceName", "authority", "multiMode", "idle_timeout", "health_check_timeout", "permit_without_stream", "initial_windows_size"); e != nil {
			return "", e
		}
	default:
		return "", fmt.Errorf("unsupported Xray transport")
	}
	for _, key := range []string{"xhttpSettings", "wsSettings", "grpcSettings", "tcpSettings", "rawSettings"} {
		if _, ok := stream[key]; ok && key != active && !(active == "rawSettings" && key == "tcpSettings") {
			return "", fmt.Errorf("conflicting Xray transport settings")
		}
	}
	for _, k := range []string{"rawSettings", "tcpSettings"} {
		if v, ok := stream[k]; ok && len(object(v)) != 0 {
			return "", fmt.Errorf("unsupported raw transport settings")
		}
	}
	return family, nil
}
func rangeValue(v any) bool {
	if n, ok := integer(v); ok {
		return n >= 0
	}
	s, ok := v.(string)
	if !ok {
		return false
	}
	parts := strings.Split(s, "-")
	if len(parts) != 2 {
		return false
	}
	a, e := strconv.Atoi(parts[0])
	b, f := strconv.Atoi(parts[1])
	return e == nil && f == nil && a >= 0 && a <= b
}
func parseXrayOutbound(input map[string]any) (Profile, error) {
	o := clone(input)
	family, e := validateXray(o)
	if e != nil {
		return Profile{}, e
	}
	delete(o, "tag")
	return finish(Profile{Family: family, Engine: "xray", Outbound: o})
}

func validateWGWS(w *WGWS) error {
	if w == nil {
		return fmt.Errorf("WGWS configuration missing")
	}
	ws := w.Websocket
	if e := fieldTypes(ws, []string{"server", "sni", "host", "path"}, []string{"tls"}, []string{"server_port"}); e != nil {
		return e
	}
	if e := allowed(ws, "server", "server_port", "tls", "sni", "host", "path", "headers"); e != nil {
		return e
	}
	if e := hostPort(ws, "server", "server_port"); e != nil {
		return e
	}
	if ws["tls"] != true {
		return fmt.Errorf("WGWS verified TLS required")
	}
	if path := str(ws, "path"); path == "" || !strings.HasPrefix(path, "/") || strings.ContainsAny(path, "\r\n\x00?#") {
		return fmt.Errorf("invalid WGWS upgrade path")
	}
	for _, k := range []string{"sni", "host"} {
		if strings.ContainsAny(str(ws, k), "\r\n\x00") {
			return fmt.Errorf("invalid WGWS header")
		}
	}
	if _, e := wgwsHeaders(ws); e != nil {
		return e
	}
	ep := w.Endpoint
	if e := fieldTypes(ep, []string{"type", "private_key"}, nil, []string{"mtu", "workers"}); e != nil {
		return e
	}
	if e := allowed(ep, "type", "address", "private_key", "peers", "mtu", "workers"); e != nil {
		return e
	}
	if str(ep, "type") != "wireguard" {
		return fmt.Errorf("WGWS requires WireGuard endpoint")
	}
	if e := require(ep, "private_key"); e != nil {
		return e
	}
	if e := stringList(ep["address"]); e != nil {
		return e
	}
	for _, v := range array(ep["address"]) {
		p, e := netip.ParsePrefix(v.(string))
		if e != nil || !p.Addr().Is4() {
			return fmt.Errorf("WGWS requires IPv4 local addresses")
		}
	}
	peers := array(ep["peers"])
	if len(peers) != 1 {
		return fmt.Errorf("WGWS requires exactly one WireGuard peer")
	}
	peer := object(peers[0])
	if e := fieldTypes(peer, []string{"public_key", "pre_shared_key"}, nil, []string{"persistent_keepalive_interval"}); e != nil {
		return e
	}
	if e := allowed(peer, "public_key", "allowed_ips", "persistent_keepalive_interval", "pre_shared_key", "reserved"); e != nil {
		return e
	}
	if e := require(peer, "public_key"); e != nil {
		return e
	}
	if e := stringList(peer["allowed_ips"]); e != nil {
		return e
	}
	hasDefault := false
	for _, v := range array(peer["allowed_ips"]) {
		p, e := netip.ParsePrefix(v.(string))
		if e != nil || !p.Addr().Is4() {
			return fmt.Errorf("WGWS requires IPv4 allowed IPs")
		}
		if p.String() == "0.0.0.0/0" {
			hasDefault = true
		}
	}
	if !hasDefault {
		return fmt.Errorf("WGWS requires full IPv4 tunnel allowed IPs")
	}
	if v, ok := peer["persistent_keepalive_interval"]; ok {
		n, valid := integer(v)
		if !valid || n < 0 || n > 65535 {
			return fmt.Errorf("invalid WireGuard keepalive")
		}
	}
	if v, ok := peer["reserved"]; ok {
		a := array(v)
		if len(a) != 3 {
			return fmt.Errorf("invalid WireGuard reserved bytes")
		}
		for _, b := range a {
			n, valid := integer(b)
			if !valid || n < 0 || n > 255 {
				return fmt.Errorf("invalid WireGuard reserved bytes")
			}
		}
	}
	if n := number(ep, "mtu", 1280); n < 576 || n > 9000 {
		return fmt.Errorf("invalid WireGuard MTU")
	}
	remote, e := netip.ParseAddrPort(w.RemoteUDP)
	if e != nil || remote.Port() == 0 || !remote.Addr().Is4() || !remote.Addr().IsLoopback() {
		return fmt.Errorf("WGWS remote UDP endpoint must be IPv4 loopback")
	}
	return nil
}
func parseWGWS(m map[string]any) (Profile, error) {
	if schema := str(m, "schema"); schema != "" && schema != "tracegate.wgws-client.v1" {
		return Profile{}, fmt.Errorf("unsupported WGWS schema")
	}
	ws := clone(object(m["websocket"]))
	tunnel := object(m["wstunnel"])
	if ws == nil || tunnel == nil || str(tunnel, "mode") != "wireguard-over-websocket" {
		return Profile{}, fmt.Errorf("native WGWS wrapper required")
	}
	if ws["server_port"] == nil {
		ws["server_port"] = 443
	}
	if ws["tls"] == nil {
		ws["tls"] = true
	}
	if ws["path"] == nil {
		ws["path"] = "/wgws"
	}
	if e := allowed(tunnel, "mode", "url", "local_udp_listen", "remote_udp_endpoint", "http_upgrade_path_prefix", "client_command"); e != nil {
		return Profile{}, e
	}
	if prefix := str(tunnel, "http_upgrade_path_prefix"); prefix != "" && prefix != strings.TrimPrefix(str(ws, "path"), "/") {
		return Profile{}, fmt.Errorf("conflicting WGWS upgrade path")
	}
	if raw := str(tunnel, "url"); raw != "" {
		u, e := url.Parse(raw)
		if e != nil || u.Scheme != "wss" || u.Hostname() != str(ws, "server") || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
			return Profile{}, fmt.Errorf("conflicting WGWS URL")
		}
		port := 443
		if u.Port() != "" {
			port, e = strconv.Atoi(u.Port())
			if e != nil {
				return Profile{}, fmt.Errorf("invalid WGWS URL port")
			}
		}
		if port != number(ws, "server_port", 443) || (u.Path != "" && u.Path != str(ws, "path")) {
			return Profile{}, fmt.Errorf("conflicting WGWS URL")
		}
	}
	endpoints := array(object(m["singbox"])["endpoints"])
	if len(endpoints) != 1 {
		return Profile{}, fmt.Errorf("WGWS requires one modern WireGuard endpoint")
	}
	ep := clone(object(endpoints[0]))
	if e := allowed(ep, "type", "tag", "detour", "system", "name", "address", "private_key", "peers", "mtu", "workers"); e != nil {
		return Profile{}, e
	}
	if ep["system"] != nil && ep["system"] != false {
		return Profile{}, fmt.Errorf("system WireGuard is unsupported")
	}
	for _, k := range []string{"tag", "detour", "system", "name"} {
		delete(ep, k)
	}
	peers := array(ep["peers"])
	if len(peers) != 1 {
		return Profile{}, fmt.Errorf("WGWS requires one peer")
	}
	peer := object(peers[0])
	if e := allowed(peer, "address", "port", "public_key", "allowed_ips", "persistent_keepalive_interval", "pre_shared_key", "reserved"); e != nil {
		return Profile{}, e
	}
	if str(peer, "address") != "127.0.0.1" {
		return Profile{}, fmt.Errorf("WGWS peer must be loopback")
	}
	port := number(peer, "port", 0)
	if port < 1 || port > 65535 {
		return Profile{}, fmt.Errorf("invalid WGWS peer port")
	}
	remote := str(tunnel, "remote_udp_endpoint")
	if remote == "" {
		remote = "127.0.0.1:" + strconv.Itoa(port)
	}
	delete(peer, "address")
	delete(peer, "port")
	w := &WGWS{Websocket: ws, Endpoint: ep, RemoteUDP: remote}
	if e := validateWGWS(w); e != nil {
		return Profile{}, e
	}
	return finish(Profile{Family: "wgws", Engine: "wstunnel", WGWS: w})
}
func validateProfile(p Profile) error {
	switch p.Engine {
	case "sing-box":
		f, e := validateSingBox(clone(p.Outbound), clone(p.Detour))
		if e != nil {
			return e
		}
		if f != p.Family {
			return fmt.Errorf("profile family mismatch")
		}
	case "xray":
		f, e := validateXray(p.Outbound)
		if e != nil {
			return e
		}
		if f != p.Family {
			return fmt.Errorf("profile family mismatch")
		}
	case "wstunnel":
		if p.Family != "wgws" || p.Outbound != nil || p.Detour != nil {
			return fmt.Errorf("invalid WGWS profile")
		}
		return validateWGWS(p.WGWS)
	default:
		return fmt.Errorf("unsupported profile engine")
	}
	if p.WGWS != nil {
		return fmt.Errorf("unexpected WGWS settings")
	}
	return nil
}

func parseURI(line string) (Profile, error) {
	if strings.HasPrefix(line, "wgws://") {
		payload := strings.TrimPrefix(line, "wgws://")
		payload = strings.Split(strings.Split(payload, "#")[0], "?")[0]
		b, e := decode64(payload)
		if e != nil {
			return Profile{}, e
		}
		v, e := decodeJSON(b)
		if e != nil {
			return Profile{}, e
		}
		m := object(v)
		if str(m, "type") == "wgws" {
			return parseWGWS(m)
		}
		return compactWGWS(m)
	}
	u, e := url.Parse(line)
	if e != nil || u == nil {
		return Profile{}, fmt.Errorf("invalid transport URI")
	}
	q, e := url.ParseQuery(u.RawQuery)
	if e != nil {
		return Profile{}, fmt.Errorf("invalid URI query")
	}
	for _, v := range q {
		if len(v) != 1 {
			return Profile{}, fmt.Errorf("duplicate URI option")
		}
	}
	if u.User == nil {
		return Profile{}, fmt.Errorf("transport credentials required")
	}
	if u.Path != "" && u.Path != "/" {
		return Profile{}, fmt.Errorf("unsupported URI authority path")
	}
	port := 443
	if u.Port() != "" {
		port, e = strconv.Atoi(u.Port())
		if e != nil {
			return Profile{}, fmt.Errorf("invalid URI port")
		}
	}
	user := u.User.Username()
	password, hasPassword := u.User.Password()
	host := u.Hostname()
	tls := map[string]any{"enabled": true, "server_name": host}
	if q.Get("sni") != "" {
		tls["server_name"] = q.Get("sni")
	}
	allowedQuery := func(keys ...string) error {
		m := map[string]any{}
		for k := range q {
			m[k] = true
		}
		return allowed(m, keys...)
	}
	switch strings.ToLower(u.Scheme) {
	case "hy2", "hysteria2":
		if e = allowedQuery("obfs", "obfs-password", "obfs_password", "obfs-min-packet-size", "obfs-max-packet-size", "sni", "insecure", "alpn", "mport", "hop-interval", "hopInterval"); e != nil {
			return Profile{}, e
		}
		if hasPassword {
			user += ":" + password
		}
		if q.Get("insecure") != "" && q.Get("insecure") != "0" && q.Get("insecure") != "false" {
			return Profile{}, fmt.Errorf("insecure TLS is unsupported")
		}
		obfsPassword := q.Get("obfs-password")
		if obfsPassword == "" {
			obfsPassword = q.Get("obfs_password")
		}
		obfs := map[string]any{"type": q.Get("obfs"), "password": obfsPassword}
		for _, item := range []struct{ query, key string }{{"obfs-min-packet-size", "min_packet_size"}, {"obfs-max-packet-size", "max_packet_size"}} {
			if s := q.Get(item.query); s != "" {
				n, e := strconv.Atoi(s)
				if e != nil {
					return Profile{}, fmt.Errorf("invalid Gecko padding")
				}
				obfs[item.key] = n
			}
		}
		o := map[string]any{"type": "hysteria2", "server": host, "server_port": port, "password": user, "obfs": obfs, "tls": tls}
		if q.Get("alpn") != "" {
			a := []any{}
			for _, v := range strings.Split(q.Get("alpn"), ",") {
				a = append(a, v)
			}
			tls["alpn"] = a
		}
		if s := q.Get("mport"); s != "" {
			a := []any{}
			for _, v := range strings.Split(s, ",") {
				v = strings.ReplaceAll(v, "-", ":")
				if !strings.Contains(v, ":") {
					v = v + ":" + v
				}
				a = append(a, v)
			}
			o["server_ports"] = a
		}
		hop := q.Get("hop-interval")
		if hop == "" {
			hop = q.Get("hopInterval")
		}
		if hop != "" {
			n, e := strconv.Atoi(hop)
			if e != nil || n < 1 {
				return Profile{}, fmt.Errorf("invalid HY2 hop interval")
			}
			o["hop_interval"] = strconv.Itoa(n) + "s"
		}
		return parseSingBoxOutbound(o, nil)
	case "vless":
		if hasPassword {
			return Profile{}, fmt.Errorf("unexpected VLESS password")
		}
		if e = allowedQuery("security", "encryption", "sni", "fp", "pbk", "sid", "spx", "type", "flow", "path", "host", "mode", "serviceName", "authority", "alpn", "allowInsecure"); e != nil {
			return Profile{}, e
		}
		if q.Get("allowInsecure") != "" && q.Get("allowInsecure") != "0" && q.Get("allowInsecure") != "false" {
			return Profile{}, fmt.Errorf("insecure TLS is unsupported")
		}
		encryption := q.Get("encryption")
		if encryption == "" {
			encryption = "none"
		}
		vuser := map[string]any{"id": user, "encryption": encryption}
		if q.Get("flow") != "" {
			vuser["flow"] = q.Get("flow")
		}
		network := q.Get("type")
		if network == "" {
			network = "raw"
		}
		for _, k := range []string{"path", "host", "mode", "serviceName", "authority"} {
			if q.Get(k) == "" {
				continue
			}
			permitted := false
			switch network {
			case "xhttp", "splithttp":
				permitted = k == "path" || k == "host" || k == "mode"
			case "ws":
				permitted = k == "path" || k == "host"
			case "grpc":
				permitted = k == "serviceName" || k == "authority" || k == "mode"
			}
			if !permitted {
				return Profile{}, fmt.Errorf("option conflicts with selected VLESS transport")
			}
		}
		if network == "grpc" && q.Get("mode") != "" && q.Get("mode") != "gun" && q.Get("mode") != "multi" {
			return Profile{}, fmt.Errorf("unsupported gRPC mode")
		}
		if q.Get("security") == "reality" && q.Get("alpn") != "" {
			return Profile{}, fmt.Errorf("REALITY ALPN option unsupported")
		}
		if q.Get("security") != "reality" && (q.Get("pbk") != "" || q.Get("sid") != "" || q.Get("spx") != "") {
			return Profile{}, fmt.Errorf("REALITY options require REALITY security")
		}
		stream := map[string]any{"network": network, "security": q.Get("security")}
		sni := str(tls, "server_name")
		fp := q.Get("fp")
		if fp == "" {
			fp = "chrome"
		}
		if q.Get("security") == "reality" {
			stream["realitySettings"] = map[string]any{"serverName": sni, "fingerprint": fp, "publicKey": q.Get("pbk"), "shortId": q.Get("sid"), "spiderX": q.Get("spx")}
		} else {
			t := map[string]any{"serverName": sni, "fingerprint": fp}
			if q.Get("alpn") != "" {
				a := []any{}
				for _, v := range strings.Split(q.Get("alpn"), ",") {
					a = append(a, v)
				}
				t["alpn"] = a
			}
			stream["tlsSettings"] = t
		}
		switch network {
		case "xhttp", "splithttp":
			x := map[string]any{"path": q.Get("path"), "mode": q.Get("mode")}
			if q.Get("host") != "" {
				x["host"] = q.Get("host")
			}
			stream["xhttpSettings"] = x
		case "ws":
			stream["wsSettings"] = map[string]any{"path": q.Get("path"), "headers": map[string]any{"Host": q.Get("host")}}
		case "grpc":
			stream["grpcSettings"] = map[string]any{"serviceName": q.Get("serviceName"), "authority": q.Get("authority"), "multiMode": q.Get("mode") == "multi"}
		case "tcp", "raw":
			if q.Get("path") != "" || q.Get("host") != "" || q.Get("mode") != "" {
				return Profile{}, fmt.Errorf("unsupported raw transport option")
			}
		}
		if network != "xhttp" && network != "splithttp" {
			return vlessURISingBox(host, port, vuser, stream)
		}
		return parseXrayOutbound(map[string]any{"protocol": "vless", "settings": map[string]any{"vnext": []any{map[string]any{"address": host, "port": port, "users": []any{vuser}}}}, "streamSettings": stream})
	case "ss":
		if e = allowedQuery("plugin"); e != nil {
			return Profile{}, e
		}
		decoded := user
		if !hasPassword {
			b, e := decode64(user)
			if e != nil {
				return Profile{}, fmt.Errorf("invalid SS2022 credentials")
			}
			decoded = string(b)
		} else {
			decoded += ":" + password
		}
		method, key, ok := strings.Cut(decoded, ":")
		if !ok {
			return Profile{}, fmt.Errorf("SS2022 credentials required")
		}
		parts := strings.Split(q.Get("plugin"), ";")
		if len(parts) == 0 || parts[0] != "shadow-tls" {
			return Profile{}, fmt.Errorf("ShadowTLS plugin required")
		}
		params := map[string]string{}
		for _, part := range parts[1:] {
			k, v, ok := strings.Cut(part, "=")
			_, exists := params[k]
			if !ok || exists {
				return Profile{}, fmt.Errorf("invalid ShadowTLS option")
			}
			switch k {
			case "host", "password", "version":
				params[k] = v
			default:
				return Profile{}, fmt.Errorf("unsupported ShadowTLS option")
			}
		}
		version := 3
		if params["version"] != "" {
			version, e = strconv.Atoi(params["version"])
			if e != nil {
				return Profile{}, fmt.Errorf("invalid ShadowTLS version")
			}
		}
		if params["host"] == "" {
			return Profile{}, fmt.Errorf("ShadowTLS handshake host required")
		}
		tls["server_name"] = params["host"]
		d := map[string]any{"type": "shadowtls", "server": host, "server_port": port, "version": version, "password": params["password"], "tls": tls}
		o := map[string]any{"type": "shadowsocks", "server": host, "server_port": port, "method": method, "password": key, "detour": "shadowtls"}
		return parseSingBoxOutbound(o, d)
	default:
		return Profile{}, fmt.Errorf("unsupported transport URI scheme")
	}
}
func compactWGWS(m map[string]any) (Profile, error) {
	if e := allowed(m, "name", "wg", "ws"); e != nil {
		return Profile{}, e
	}
	wg := object(m["wg"])
	ws := clone(object(m["ws"]))
	if wg == nil || ws == nil {
		return Profile{}, fmt.Errorf("compact WGWS requires wg and ws")
	}
	if e := allowed(wg, "private_key", "peer_public_key", "address", "local_address", "allowed_ips", "keepalive", "persistent_keepalive", "pre_shared_key", "mtu"); e != nil {
		return Profile{}, e
	}
	addr := wg["address"]
	if addr == nil {
		addr = wg["local_address"]
	}
	ips := wg["allowed_ips"]
	if ips == nil {
		ips = []any{"0.0.0.0/0"}
	}
	keepalive := number(wg, "keepalive", number(wg, "persistent_keepalive", 25))
	peer := map[string]any{"public_key": str(wg, "peer_public_key"), "allowed_ips": ips, "persistent_keepalive_interval": keepalive}
	if p := str(wg, "pre_shared_key"); p != "" {
		peer["pre_shared_key"] = p
	}
	ep := map[string]any{"type": "wireguard", "address": addr, "private_key": str(wg, "private_key"), "peers": []any{peer}, "mtu": number(wg, "mtu", 1280)}
	if ws["server_port"] == nil {
		ws["server_port"] = 443
	}
	if ws["tls"] == nil {
		ws["tls"] = true
	}
	if ws["path"] == nil {
		ws["path"] = "/wgws"
	}
	// Validate and clone before merging; authentication headers must survive.
	h, e := wgwsHeaders(ws)
	if e != nil {
		return Profile{}, e
	}
	if len(h) > 0 {
		ws["headers"] = h
	}
	w := &WGWS{Websocket: ws, Endpoint: ep, RemoteUDP: "127.0.0.1:51820"}
	if e := validateWGWS(w); e != nil {
		return Profile{}, e
	}
	return finish(Profile{Family: "wgws", Engine: "wstunnel", WGWS: w})
}

// geckoBundleArtifact reads only the scalar mapping emitted by Tracegate's
// official exporter. It is not a general YAML importer; unknown/nonscalar YAML
// constructs fail explicitly. Network credentials/TLS must agree with the URI.
func geckoBundleArtifact(p Profile, artifacts []any) (Profile, error) {
	count := 0
	for _, v := range artifacts {
		a := object(v)
		if str(a, "kind") == "file" && strings.HasSuffix(str(a, "filename"), ".hysteria.yaml") {
			count++
		}
	}
	if count > 1 {
		return Profile{}, fmt.Errorf("duplicate Gecko YAML artifact")
	}
	for _, v := range artifacts {
		a := object(v)
		if str(a, "kind") != "file" || !strings.HasSuffix(str(a, "filename"), ".hysteria.yaml") {
			continue
		}
		b, e := decode64(str(a, "contentBase64"))
		if e != nil {
			return Profile{}, fmt.Errorf("invalid Gecko YAML artifact")
		}
		values := map[string]string{}
		sections := []string{}
		seen := map[string]bool{}
		known := map[string]bool{"server": true, "auth": true, "tls": true, "tls.sni": true, "tls.insecure": true, "obfs": true, "obfs.type": true, "obfs.gecko": true, "obfs.gecko.password": true, "obfs.gecko.minPacketSize": true, "obfs.gecko.maxPacketSize": true, "bandwidth": true, "bandwidth.up": true, "bandwidth.down": true, "socks5": true, "socks5.listen": true, "socks5.username": true, "socks5.password": true, "socks5.disableUDP": true}
		for _, line := range strings.Split(string(b), "\n") {
			if strings.TrimSpace(line) == "" {
				continue
			}
			if strings.ContainsRune(line, '\t') {
				return Profile{}, fmt.Errorf("unsupported Gecko YAML indentation")
			}
			indent := len(line) - len(strings.TrimLeft(line, " "))
			if indent%2 != 0 || indent > 4 {
				return Profile{}, fmt.Errorf("unsupported Gecko YAML indentation")
			}
			level := indent / 2
			if level > len(sections) {
				return Profile{}, fmt.Errorf("invalid Gecko YAML mapping")
			}
			sections = sections[:level]
			key, val, ok := strings.Cut(strings.TrimSpace(line), ":")
			if !ok || key == "" {
				return Profile{}, fmt.Errorf("unsupported Gecko YAML syntax")
			}
			path := strings.Join(append(append([]string{}, sections...), key), ".")
			if !known[path] || seen[path] {
				return Profile{}, fmt.Errorf("unknown or duplicate Gecko YAML field")
			}
			seen[path] = true
			val = strings.TrimSpace(val)
			if val == "" {
				sections = append(sections, key)
				continue
			}
			if strings.HasPrefix(val, "\"") {
				decoded, e := strconv.Unquote(val)
				if e != nil {
					return Profile{}, fmt.Errorf("unsupported Gecko YAML scalar")
				}
				val = decoded
			} else if strings.HasPrefix(val, "'") {
				if len(val) < 2 || !strings.HasSuffix(val, "'") {
					return Profile{}, fmt.Errorf("unsupported multiline Gecko YAML")
				}
				val = strings.ReplaceAll(val[1:len(val)-1], "''", "'")
			} else if strings.ContainsAny(val[:1], "&*!|>[{") {
				return Profile{}, fmt.Errorf("unsupported Gecko YAML scalar")
			}
			values[path] = val
		}
		obfs := object(p.Outbound["obfs"])
		tls := object(p.Outbound["tls"])
		if str(obfs, "type") != "gecko" || values["obfs.type"] != "gecko" || values["auth"] != str(p.Outbound, "password") || values["obfs.gecko.password"] != str(obfs, "password") || values["server"] != str(p.Outbound, "server")+":"+strconv.Itoa(number(p.Outbound, "server_port", 443)) || values["tls.sni"] != str(tls, "server_name") || values["tls.insecure"] != "false" {
			return Profile{}, fmt.Errorf("Gecko YAML and URI disagree")
		}
		for _, field := range []struct{ path, key string }{{"obfs.gecko.minPacketSize", "min_packet_size"}, {"obfs.gecko.maxPacketSize", "max_packet_size"}} {
			n, e := strconv.Atoi(values[field.path])
			if e != nil {
				return Profile{}, fmt.Errorf("invalid Gecko YAML padding")
			}
			obfs[field.key] = n
		}
		for _, field := range []struct{ path, key string }{{"bandwidth.up", "up_mbps"}, {"bandwidth.down", "down_mbps"}} {
			val := values[field.path]
			if val == "" {
				continue
			}
			if !strings.HasSuffix(val, " mbps") {
				return Profile{}, fmt.Errorf("unsupported Gecko YAML bandwidth")
			}
			n, e := strconv.Atoi(strings.TrimSuffix(val, " mbps"))
			if e != nil || n < 1 {
				return Profile{}, fmt.Errorf("invalid Gecko YAML bandwidth")
			}
			p.Outbound[field.key] = n
		}
		return parseSingBoxOutbound(p.Outbound, nil)
	}
	return p, nil
}

func vlessURISingBox(host string, port int, user, stream map[string]any) (Profile, error) {
	if str(user, "encryption") != "none" {
		return Profile{}, fmt.Errorf("unsupported VLESS encryption")
	}
	o := map[string]any{"type": "vless", "server": host, "server_port": port, "uuid": str(user, "id")}
	if str(user, "flow") != "" {
		o["flow"] = str(user, "flow")
	}
	tls := map[string]any{"enabled": true}
	switch str(stream, "security") {
	case "tls":
		t := object(stream["tlsSettings"])
		tls["server_name"] = str(t, "serverName")
		tls["utls"] = map[string]any{"enabled": true, "fingerprint": str(t, "fingerprint")}
		if a, ok := t["alpn"]; ok {
			tls["alpn"] = a
		}
	case "reality":
		r := object(stream["realitySettings"])
		if x := str(r, "spiderX"); x != "" && x != "/" {
			return Profile{}, fmt.Errorf("custom REALITY spider path requires native Xray JSON")
		}
		tls["server_name"] = str(r, "serverName")
		tls["utls"] = map[string]any{"enabled": true, "fingerprint": str(r, "fingerprint")}
		tls["reality"] = map[string]any{"enabled": true, "public_key": str(r, "publicKey"), "short_id": str(r, "shortId")}
	default:
		return Profile{}, fmt.Errorf("verified VLESS TLS/REALITY required")
	}
	o["tls"] = tls
	switch str(stream, "network") {
	case "tcp", "raw", "":
	case "ws":
		w := object(stream["wsSettings"])
		tr := map[string]any{"type": "ws", "path": str(w, "path")}
		h := object(w["headers"])
		if str(h, "Host") != "" {
			tr["headers"] = h
		}
		o["transport"] = tr
	case "grpc":
		g := object(stream["grpcSettings"])
		if g["multiMode"] == true {
			return Profile{}, fmt.Errorf("gRPC multi mode requires native Xray JSON")
		}
		if a := str(g, "authority"); a != "" && a != str(tls, "server_name") {
			return Profile{}, fmt.Errorf("custom gRPC authority requires native Xray JSON")
		}
		o["transport"] = map[string]any{"type": "grpc", "service_name": str(g, "serviceName")}
	default:
		return Profile{}, fmt.Errorf("unsupported VLESS transport")
	}
	return parseSingBoxOutbound(o, nil)
}

// Normalize only Host spelling, preserving every accepted authenticated header.
// Both native and compact paths use the same case-insensitive conflict rule.
func wgwsHeaders(ws map[string]any) (map[string]any, error) {
	raw, exists := ws["headers"]
	if exists {
		if e := headers(raw); e != nil {
			return nil, e
		}
	}
	h := map[string]any{}
	host := str(ws, "host")
	seenHost := false
	for key, value := range object(raw) {
		if strings.EqualFold(key, "Host") {
			if seenHost || (host != "" && value != host) {
				return nil, fmt.Errorf("conflicting WGWS Host header")
			}
			seenHost = true
			if host == "" {
				host = value.(string)
			}
		} else {
			h[key] = value
		}
	}
	if host != "" || seenHost {
		h["Host"] = host
	}
	return h, nil
}

// validateRandomSNI matches the opt-in audited client's deliberately narrow DNS
// and TLS contract. Rendering retains the policy; only the engine's QUIC dial
// callback chooses a session name.
func validateRandomSNI(o map[string]any) error {
	suffix, ok := o["flr_random_sni_suffix"].(string)
	if !ok || len(suffix) > 220 || !randomSNIDNSName(suffix) || net.ParseIP(suffix) != nil {
		return fmt.Errorf("invalid random SNI suffix")
	}
	endpoint := net.ParseIP(str(o, "server"))
	if endpoint == nil || endpoint.To4() == nil {
		return fmt.Errorf("random SNI requires a fixed IPv4 endpoint")
	}
	t := object(o["tls"])
	for _, key := range []string{"utls", "reality", "ech", "engine", "disable_sni"} {
		if _, present := t[key]; present {
			return fmt.Errorf("unsupported random SNI TLS option")
		}
	}
	seed := str(t, "server_name")
	label := strings.TrimSuffix(seed, "."+suffix)
	if t["enabled"] != true || t["insecure"] != nil && t["insecure"] != false || seed == label || len(seed) > 253 || !randomSNILabel(label) {
		return fmt.Errorf("random SNI requires a verified one-label seed name")
	}
	return nil
}
func randomSNIDNSName(name string) bool {
	labels := strings.Split(name, ".")
	if len(labels) < 2 {
		return false
	}
	for _, label := range labels {
		if !randomSNILabel(label) {
			return false
		}
	}
	return true
}
func randomSNILabel(label string) bool {
	if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
		return false
	}
	for _, c := range []byte(label) {
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
			return false
		}
	}
	return true
}

// bbrProfilePattern is deliberately a token check, not an enumeration: the
// value set of sing-box 1.14 could not be confirmed offline ("standard" is the
// documented default). The router's engine check (sing-box check) still
// rejects a value the installed engine does not define before it is stored.
var bbrProfilePattern = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,31}$`)

// maxHopInterval bounds port-hopping timers to a sane day; sing-box itself
// accepts any positive duration.
const maxHopInterval = 24 * time.Hour

// validateHY2Options checks the sing-box 1.14 Hysteria2 additions:
// hop_interval_max (randomized hop interval upper bound), bbr_profile and
// disable_chrome_parrot (opt out of the default Chrome QUIC fingerprint).
// Types were checked by fieldTypes; this adds the value and range rules.
func validateHY2Options(o map[string]any) error {
	if v, ok := o["hop_interval_max"]; ok {
		max, e := hopDuration(v)
		if e != nil {
			return fmt.Errorf("invalid HY2 maximum hop interval")
		}
		if v, ok := o["hop_interval"]; ok {
			min, e := hopDuration(v)
			if e != nil {
				return fmt.Errorf("invalid hop interval")
			}
			if max < min {
				return fmt.Errorf("HY2 maximum hop interval is below hop interval")
			}
		}
	}
	if v, ok := o["bbr_profile"]; ok {
		if s, _ := v.(string); !bbrProfilePattern.MatchString(s) {
			return fmt.Errorf("invalid HY2 BBR profile")
		}
	}
	return nil
}
func hopDuration(v any) (time.Duration, error) {
	s, ok := v.(string)
	if !ok || s == "" || strings.ContainsAny(s, " +-") {
		return 0, fmt.Errorf("invalid duration")
	}
	d, e := time.ParseDuration(s)
	if e != nil || d <= 0 || d > maxHopInterval {
		return 0, fmt.Errorf("invalid duration")
	}
	return d, nil
}
