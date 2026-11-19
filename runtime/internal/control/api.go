package control

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"github.com/MyHeartRaces/FLR/runtime/internal/lan"
	"github.com/MyHeartRaces/FLR/runtime/internal/profile"
	"github.com/MyHeartRaces/FLR/runtime/internal/validation"
	"io"
	"net"
	"os"
	"regexp"
	"time"
)

// deviceLAN is the router's current LAN for pre-validating device requests;
// the controller repeats the check against its own LAN before applying. It is
// zero when discovery fails, so no new profile is accepted against the legacy
// fallback.
func deviceLAN() lan.LAN {
	l, e := lan.Resolve(lan.Interface)
	if e != nil {
		return lan.LAN{}
	}
	return l
}

const MaxAPIBytes = 1 << 20
const APISocket = "/var/run/flr-runtime/api.sock"

type APIRequest struct {
	Data               string          `json:"data,omitempty"`
	Metadata           json.RawMessage `json:"metadata,omitempty"`
	Selection          json.RawMessage `json:"selection,omitempty"`
	Order              json.RawMessage `json:"order,omitempty"`
	Reselect           bool            `json:"reselect,omitempty"`
	ExpectedGeneration *uint64         `json:"expected_generation,omitempty"`
	Operation          string          `json:"operation"`
	Content            string          `json:"content,omitempty"`
	URL                string          `json:"url,omitempty"`
	ID                 string          `json:"id,omitempty"`
	Enabled            *bool           `json:"enabled,omitempty"`
	Priority           *int            `json:"priority,omitempty"`
	ServerGroup        *string         `json:"server_group,omitempty"`
	Client             string          `json:"client,omitempty"`
	Value              string          `json:"value,omitempty"`
	Settings           json.RawMessage `json:"settings,omitempty"`
	Activate           bool            `json:"activate,omitempty"`
	Accepted           bool            `json:"accepted,omitempty"`
	// Routing carries the arguments of the routing-* operations
	// (controller/policy_api.go, docs/ROUTER-API.md).
	Routing json.RawMessage `json:"routing,omitempty"`
}

func strictJSON(raw []byte, v any) error {
	if e := CheckJSON(raw); e != nil {
		return e
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if e := d.Decode(v); e != nil {
		return fmt.Errorf("invalid JSON request")
	}
	var extra any
	if e := d.Decode(&extra); e != io.EOF {
		return fmt.Errorf("trailing JSON request")
	}
	return nil
}
func (r APIRequest) Write() bool {
	switch r.Operation {
	case "status", "profiles", "help", "capabilities", "connection-list", "diagnostics":
		return false
	case "routing-policy", "routing-entries", "routing-rules", "routing-roscomvpn-status":
		return false
	case "settings":
		return len(r.Settings) != 0
	case "primary-awg":
		return r.Content != "" || r.Activate
	default:
		return true
	}
}
func ParseAPI(raw []byte, rpc, readOnly bool) (APIRequest, error) {
	var r APIRequest
	if len(raw) > MaxAPIBytes {
		return r, fmt.Errorf("request too large")
	}
	if rpc {
		var wrapper struct {
			Request string `json:"request"`
			// rpcd supplies this metadata after ubus authenticates the caller.
			// Never forward it or use it to authorize a controller operation.
			Session string `json:"ubus_rpc_session,omitempty"`
		}
		if e := strictJSON(raw, &wrapper); e != nil {
			return r, e
		}
		raw = []byte(wrapper.Request)
	}
	if e := strictJSON(raw, &r); e != nil {
		return r, e
	}
	if len(bytes.TrimSpace(raw)) == 0 || bytes.TrimSpace(raw)[0] != '{' {
		return r, fmt.Errorf("request must be object")
	}
	if readOnly && r.Write() {
		return r, fmt.Errorf("read-only method rejects writes")
	}
	// Each operation permits only its own fields. A forged operation cannot
	// smuggle a write payload through a read-only dispatch method.
	permitted := map[string]map[string]bool{
		"diagnostics":        {},
		"diagnostics-export": {"value": true},
		"connection-list":    {},
		"connection-import":  {"data": true, "url": true, "expected_generation": true},
		"connection-replace": {"id": true, "data": true, "url": true, "expected_generation": true},
		"connection-update":  {"id": true, "metadata": true, "expected_generation": true},
		"connection-delete":  {"id": true, "selection": true, "expected_generation": true},
		"selection":          {"selection": true, "expected_generation": true},
		"connection-order":   {"order": true, "reselect": true, "expected_generation": true},
		"connection-test":    {"id": true, "expected_generation": true},
		// Export returns credentials. It is not listed as a read in Write(), so
		// the read-only rpcd method refuses it.
		"connection-export": {"id": true, "expected_generation": true},
		"vpn-activate":      {"accepted": true, "expected_generation": true},
		"status":            {}, "profiles": {}, "help": {}, "capabilities": {}, "refresh": {},
		"import": {"content": true, "url": true}, "select": {"id": true},
		"profile-update": {"id": true, "enabled": true, "priority": true, "server_group": true},
		"profile-delete": {"id": true}, "device": {"client": true, "value": true},
		"settings": {"settings": true}, "primary-awg": {"content": true, "activate": true},
		"rollback-confirm": {"accepted": true},
	}
	// Routing policy operations take their arguments in one object. The
	// export returns the private routing lists, so like connection-export it
	// is not a read and the read-only method refuses it.
	for _, name := range []string{"routing-policy", "routing-entries", "routing-rules", "routing-rule-add", "routing-rule-update", "routing-rule-delete", "routing-apply", "routing-export", "routing-import-begin", "routing-import-chunk", "routing-import-commit", "routing-import-abort", "routing-reset", "routing-restore-backup", "routing-roscomvpn-import", "routing-roscomvpn-status"} {
		permitted[name] = map[string]bool{"routing": true}
	}
	fields, ok := permitted[r.Operation]
	if !ok {
		return r, fmt.Errorf("unknown operation")
	}
	var object map[string]json.RawMessage
	if e := json.Unmarshal(raw, &object); e != nil {
		return r, fmt.Errorf("invalid request object")
	}
	for k := range object {
		if k != "operation" && !fields[k] {
			return r, fmt.Errorf("unexpected operation argument")
		}
	}
	idRE := regexp.MustCompile(`^[a-z0-9_-]{1,80}$`)
	// Export changes nothing, so its generation check is optional; when given,
	// it must still name a real generation.
	if fields["expected_generation"] && (r.ExpectedGeneration == nil && r.Operation != "connection-export" || r.ExpectedGeneration != nil && *r.ExpectedGeneration == 0) {
		return r, fmt.Errorf("current generation required")
	}
	switch r.Operation {
	case "connection-import", "connection-replace":
		if (r.Data == "") == (r.URL == "") {
			return r, fmt.Errorf("import needs exactly data or url")
		}
		if r.Operation == "connection-replace" && (!idRE.MatchString(r.ID) || r.ID == "auto") {
			return r, fmt.Errorf("invalid connection ID")
		}
	case "connection-update", "connection-delete", "connection-test", "connection-export":
		if !idRE.MatchString(r.ID) || r.ID == "auto" {
			return r, fmt.Errorf("invalid connection ID")
		}
		if r.Operation == "connection-update" {
			var metadata struct {
				Name         *string `json:"name"`
				Group        *string `json:"group"`
				Enabled      *bool   `json:"enabled"`
				RoamPorts    *string `json:"roam_ports"`
				RoamInterval *int    `json:"roam_interval"`
			}
			if !apiObject(r.Metadata) || strictJSON(r.Metadata, &metadata) != nil || (metadata.Name == nil && metadata.Group == nil && metadata.Enabled == nil && metadata.RoamPorts == nil && metadata.RoamInterval == nil) {
				return r, fmt.Errorf("invalid or empty connection metadata")
			}
			var rawFields map[string]json.RawMessage
			json.Unmarshal(r.Metadata, &rawFields)
			for _, value := range rawFields {
				if bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
					return r, fmt.Errorf("null connection metadata")
				}
			}
		}
		if len(r.Selection) > 0 && validateAPISelection(r.Selection) != nil {
			return r, fmt.Errorf("invalid connection selection")
		}
	case "selection":
		if err := validateAPISelection(r.Selection); err != nil {
			return r, err
		}
	case "connection-order":
		var order struct {
			Families    []string            `json:"families"`
			Connections map[string][]string `json:"connections"`
		}
		if !apiObject(r.Order) || strictJSON(r.Order, &order) != nil || order.Families == nil || order.Connections == nil {
			return r, fmt.Errorf("invalid connection order object")
		}
		for _, list := range order.Connections {
			if list == nil {
				return r, fmt.Errorf("null connection order list")
			}
		}
	case "vpn-activate":
		if !r.Accepted {
			return r, fmt.Errorf("explicit guarded activation acceptance required")
		}
	case "import":
		if (r.Content == "") == (r.URL == "") {
			return r, fmt.Errorf("import needs exactly content or url")
		}
	case "select", "profile-update", "profile-delete":
		if !idRE.MatchString(r.ID) {
			return r, fmt.Errorf("invalid profile ID")
		}
		if r.Operation != "select" && r.ID == "auto" {
			return r, fmt.Errorf("invalid profile ID")
		}
		if r.Operation == "profile-update" && r.Enabled == nil && r.Priority == nil && r.ServerGroup == nil {
			return r, fmt.Errorf("empty profile update")
		}
		if r.Priority != nil {
			if e := profile.ValidatePriority(*r.Priority); e != nil {
				return r, e
			}
		}
		if r.ServerGroup != nil && profile.ValidateGroup(*r.ServerGroup) != nil {
			return r, fmt.Errorf("invalid server group")
		}
	case "device":
		if _, e := Parse([]byte(fmt.Sprintf(`{"command":"profile","client":%q,"value":%q}`, r.Client, r.Value)), deviceLAN()); e != nil {
			return r, fmt.Errorf("device needs LAN IPv4 and auto/general/games/direct")
		}
	case "settings":
		if len(r.Settings) > 0 && (bytes.Equal(r.Settings, []byte("null")) || r.Settings[0] != '{') {
			return r, fmt.Errorf("settings must be object")
		}
	case "routing-policy", "routing-entries", "routing-rules", "routing-rule-add", "routing-rule-update", "routing-rule-delete", "routing-apply", "routing-export", "routing-import-begin", "routing-import-chunk", "routing-import-commit", "routing-import-abort", "routing-reset", "routing-restore-backup", "routing-roscomvpn-import", "routing-roscomvpn-status":
		if len(r.Routing) > 0 && (!apiObject(r.Routing) || CheckJSON(r.Routing) != nil) {
			return r, fmt.Errorf("routing arguments must be an object")
		}
	case "rollback-confirm":
		if !r.Accepted {
			return r, fmt.Errorf("explicit LAN/WAN connectivity acceptance required")
		}
	case "primary-awg":
		if len(r.Content) > 65536 {
			return r, fmt.Errorf("AWG configuration too large")
		}
	}
	return r, nil
}

func apiObject(raw []byte) bool {
	raw = bytes.TrimSpace(raw)
	return len(raw) > 0 && raw[0] == '{'
}
func validateAPISelection(raw []byte) error {
	var value struct {
		Mode   string `json:"mode"`
		Family string `json:"family,omitempty"`
		ID     string `json:"id,omitempty"`
	}
	if !apiObject(raw) || strictJSON(raw, &value) != nil {
		return fmt.Errorf("invalid connection selection object")
	}
	var fields map[string]json.RawMessage
	json.Unmarshal(raw, &fields)
	for _, field := range fields {
		if bytes.Equal(bytes.TrimSpace(field), []byte("null")) {
			return fmt.Errorf("null selection field")
		}
	}
	switch value.Mode {
	case "auto":
		if value.Family == "" && value.ID == "" {
			return nil
		}
	case "transport":
		if value.ID == "" && regexp.MustCompile(`^[a-z0-9_]{1,20}$`).MatchString(value.Family) {
			return nil
		}
	case "connection":
		if value.Family == "" && regexp.MustCompile(`^[a-z0-9_-]{1,80}$`).MatchString(value.ID) {
			return nil
		}
	}
	return fmt.Errorf("invalid connection selection mode")
}

// ServeAPI is a separate root-owned socket. The CLI validates rpcd's wrapper
// and read-only mode before forwarding, and the server validates plain JSON
// again. Directory 0700/socket 0600 prevent non-root callers bypassing rpcd ACL.
func ServeAPI(ctx context.Context, handler func(APIRequest) (any, error)) error {
	if e := os.MkdirAll("/var/run/flr-runtime", 0700); e != nil {
		return e
	}
	_ = os.Remove(APISocket)
	l, e := net.Listen("unix", APISocket)
	if e != nil {
		return e
	}
	defer l.Close()
	defer os.Remove(APISocket)
	if e = os.Chmod(APISocket, 0600); e != nil {
		return e
	}
	go func() { <-ctx.Done(); l.Close() }()
	for {
		conn, e := l.Accept()
		if e != nil {
			if ctx.Err() != nil {
				return nil
			}
			return e
		}
		go func(conn net.Conn) {
			defer conn.Close()
			conn.SetDeadline(time.Now().Add(30 * time.Second))
			// JSON strings can contain escaped newlines, never literal framing newlines.
			var request json.RawMessage
			decoder := json.NewDecoder(io.LimitReader(conn, MaxAPIBytes+1))
			err := decoder.Decode(&request)
			var data any
			if err == nil {
				var r APIRequest
				r, err = ParseAPI(request, false, false)
				if err == nil {
					data, err = handler(r)
				}
			}
			reply := Reply{OK: err == nil, Data: data}
			if err != nil {
				reply.Error = "invalid or failed API operation"
				if len(request) > 0 {
					reply.Error = err.Error()
					reply.ErrorDetail = validation.Detail(err)
				}
			}
			json.NewEncoder(conn).Encode(reply)
		}(conn)
	}
}
func CallAPI(r APIRequest) (any, error) {
	c, e := net.DialTimeout("unix", APISocket, 2*time.Second)
	if e != nil {
		return nil, e
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(30 * time.Second))
	if e = json.NewEncoder(c).Encode(r); e != nil {
		return nil, e
	}
	var reply Reply
	if e = json.NewDecoder(io.LimitReader(c, 2*MaxAPIBytes)).Decode(&reply); e != nil {
		return nil, fmt.Errorf("controller API unavailable")
	}
	if !reply.OK {
		if reply.ErrorDetail != nil {
			return reply.Data, reply.ErrorDetail
		}
		return reply.Data, fmt.Errorf("%s", reply.Error)
	}
	return reply.Data, nil
}
