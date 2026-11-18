// Package validation contains only bounded public reasons. Raw parser/native
// errors must never be serialized: unmatched errors use a fixed fallback.
package validation

import (
	"errors"
	"fmt"
)

type Error struct {
	Code      string `json:"code"`
	Message   string `json:"message"`
	Field     string `json:"field,omitempty"`
	Item      int    `json:"item,omitempty"`
	Component string `json:"component,omitempty"`
}

func (e *Error) Error() string {
	field := e.Field
	if e.Component != "" {
		field = e.Component + "." + field
	}
	if e.Item > 0 {
		return fmt.Sprintf("%s (item %d, %s): %s", e.Code, e.Item, field, e.Message)
	}
	return e.Code + ": " + e.Message
}
func Detail(err error) *Error {
	var e *Error
	if errors.As(err, &e) {
		copy := *e
		return &copy
	}
	return nil
}
func Public(err error) *Error {
	if e := Detail(err); e != nil {
		return e
	}
	if e, ok := reasons[err.Error()]; ok {
		copy := e
		return &copy
	}
	return &Error{Code: "invalid_profile", Message: "Check JSON/URI structure and required supported transport fields.", Field: "content"}
}
func At(err error, item int) error {
	e := Public(err)
	// Preserve the outermost batch's user-visible one-based item position.
	e.Item = item
	return e
}
