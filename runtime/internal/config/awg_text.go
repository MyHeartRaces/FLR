package config

import (
	"fmt"
	"reflect"
	"sort"
	"strings"
)

// AWGText serializes and revalidates native fields without hooks or file paths.
func AWGText(fields map[string]string) ([]byte, error) {
	peer := map[string]bool{"PublicKey": true, "PresharedKey": true, "Endpoint": true, "AllowedIPs": true, "PersistentKeepalive": true}
	keys := make([]string, 0, len(fields))
	for key, value := range fields {
		if strings.ContainsAny(key+value, "\r\n\x00") {
			return nil, fmt.Errorf("invalid AWG native field")
		}
		keys = append(keys, key)
	}
	sort.Strings(keys)
	var text strings.Builder
	for _, section := range []string{"Interface", "Peer"} {
		text.WriteString("[" + section + "]\n")
		for _, key := range keys {
			if peer[key] == (section == "Peer") {
				text.WriteString(key + " = " + fields[key] + "\n")
			}
		}
	}
	raw := []byte(text.String())
	parsed, err := ParseAWG(raw)
	if err != nil || !reflect.DeepEqual(parsed, fields) {
		return nil, fmt.Errorf("invalid canonical AWG fields")
	}
	return raw, nil
}
