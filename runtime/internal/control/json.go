package control

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
)

// CheckJSON rejects duplicate keys at every nesting level and bounds depth.
// encoding/json alone otherwise silently accepts the final repeated value.
func CheckJSON(raw []byte) error {
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	var value func(int) error
	value = func(depth int) error {
		if depth > 64 {
			return fmt.Errorf("JSON nesting limit")
		}
		token, e := d.Token()
		if e != nil {
			return fmt.Errorf("invalid JSON")
		}
		delimiter, ok := token.(json.Delim)
		if !ok {
			return nil
		}
		switch delimiter {
		case '{':
			keys := map[string]bool{}
			for d.More() {
				token, e = d.Token()
				key, ok := token.(string)
				if e != nil || !ok || keys[key] {
					return fmt.Errorf("duplicate or invalid JSON field")
				}
				keys[key] = true
				if e = value(depth + 1); e != nil {
					return e
				}
			}
			token, e = d.Token()
			if e != nil || token != json.Delim('}') {
				return fmt.Errorf("invalid JSON object")
			}
		case '[':
			for d.More() {
				if e = value(depth + 1); e != nil {
					return e
				}
			}
			token, e = d.Token()
			if e != nil || token != json.Delim(']') {
				return fmt.Errorf("invalid JSON array")
			}
		default:
			return fmt.Errorf("invalid JSON delimiter")
		}
		return nil
	}
	if e := value(0); e != nil {
		return e
	}
	if _, e := d.Token(); e != io.EOF {
		return fmt.Errorf("trailing JSON")
	}
	return nil
}
