package profile

import (
	"fmt"
	"strings"
	"unicode/utf8"
)

const MinPriority = -1000000
const MaxPriority = 1000000
const MaxGroupBytes = 80

// Preserve the existing registry contract, including Unicode group labels and
// negative priorities, at every import, settings and edit boundary.
func ValidateGroup(group string) error {
	if !utf8.ValidString(group) || len(group) > MaxGroupBytes || strings.ContainsAny(group, "\r\n\x00") || strings.Contains(group, "://") {
		return fmt.Errorf("invalid server group")
	}
	return nil
}
func ValidatePriority(priority int) error {
	if priority < MinPriority || priority > MaxPriority {
		return fmt.Errorf("priority must be -1000000..1000000")
	}
	return nil
}
