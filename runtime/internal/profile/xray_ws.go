package profile

import (
	"fmt"
	"net/url"
	"strconv"
	"strings"
)

// Xray uses an owned ed query, not the legacy early-data JSON fields. Reject
// unsupported semantics at import and use the same adapter during rendering.
func nativeXrayWS(w map[string]any) (map[string]any, error) {
	if header, exists := w["earlyDataHeaderName"]; exists {
		name, ok := header.(string)
		if !ok || !strings.EqualFold(name, "Sec-WebSocket-Protocol") {
			return nil, fmt.Errorf("Xray WS earlyDataHeaderName only supports Sec-WebSocket-Protocol")
		}
	}
	max, present := 0, false
	if value, exists := w["maxEarlyData"]; exists {
		var ok bool
		max, ok = integer(value)
		if !ok || max < 0 || max > 2147483647 {
			return nil, fmt.Errorf("Xray WS maxEarlyData must be an integer from 0 to 2147483647")
		}
		present = true
	}
	path := str(w, "path")
	u, err := url.Parse(path)
	if err != nil {
		return nil, fmt.Errorf("invalid Xray WS path")
	}
	// ParseQuery drops invalid pairs while returning an error. Detect the
	// reserved key in raw pairs first, including ambiguous semicolon forms,
	// so malformed ed cannot disappear when maxEarlyData is absent or zero.
	hasED := false
	for _, part := range strings.FieldsFunc(u.RawQuery, func(c rune) bool { return c == '&' || c == ';' }) {
		key, keyErr := url.QueryUnescape(strings.SplitN(part, "=", 2)[0])
		if keyErr == nil && key == "ed" {
			hasED = true
			break
		}
	}
	q, err := url.ParseQuery(u.RawQuery)
	if err != nil && (max > 0 || hasED) {
		return nil, fmt.Errorf("invalid Xray WS query")
	}
	ed, existing := 0, false
	if values, exists := q["ed"]; exists {
		if len(values) != 1 {
			return nil, fmt.Errorf("Xray WS ed query must occur exactly once")
		}
		value, parseErr := strconv.ParseUint(values[0], 10, 31)
		if parseErr != nil || strconv.FormatUint(value, 10) != values[0] {
			return nil, fmt.Errorf("Xray WS ed query must be a canonical integer from 0 to 2147483647")
		}
		ed, existing = int(value), true
		if present && ed != max {
			return nil, fmt.Errorf("Xray WS ed query conflicts with maxEarlyData")
		}
	}
	if !existing {
		ed = max
	}
	// Native Build removes ed and re-encodes the remaining query. Only accept
	// combinations for which that normalization preserves every other byte.
	if existing || ed > 0 {
		remaining := u.RawQuery
		if existing {
			parts := []string{}
			for _, part := range strings.Split(u.RawQuery, "&") {
				key, _ := url.QueryUnescape(strings.SplitN(part, "=", 2)[0])
				if key != "ed" {
					parts = append(parts, part)
				}
			}
			remaining = strings.Join(parts, "&")
			q.Del("ed")
		}
		if q.Encode() != remaining || u.String() != path {
			return nil, fmt.Errorf("Xray WS early data would normalize the required path or query")
		}
	}
	if ed > 0 {
		for name := range object(w["headers"]) {
			if strings.EqualFold(name, "Sec-WebSocket-Protocol") {
				return nil, fmt.Errorf("Xray WS early data conflicts with the required Sec-WebSocket-Protocol header")
			}
		}
	}
	result := clone(w)
	delete(result, "maxEarlyData")
	delete(result, "earlyDataHeaderName")
	if !existing && ed > 0 {
		// Append only our query; native removal recovers the original query.
		if u.RawQuery != "" {
			u.RawQuery += "&"
		}
		u.RawQuery += "ed=" + strconv.Itoa(ed)
		result["path"] = u.String()
	}
	return result, nil
}
