package validation

import (
	"fmt"
	"strings"
	"testing"
)

func TestPublicReasonsNeverEchoUnmatchedInputOrNativeErrors(t *testing.T) {
	for _, input := range []string{"https://user:PRIVATE_SECRET@example.com/token", "unsupported configuration field PRIVATE_SECRET", "native stderr PRIVATE_SECRET"} {
		e := Public(fmt.Errorf("%s", input))
		if e.Code != "invalid_profile" || strings.Contains(e.Error(), "PRIVATE_SECRET") || strings.Contains(e.Error(), input) {
			t.Fatal("unchecked reason exposed")
		}
	}
	for _, e := range reasons {
		if len(e.Code) > 32 || len(e.Message) > 400 || len(e.Field) > 80 || e.Code == "" || e.Message == "" {
			t.Fatal("unbounded reason")
		}
	}
	e := At(fmt.Errorf("duplicate profile identity"), 2)
	if Detail(e).Item != 2 || Detail(e).Code != "duplicate_profile" {
		t.Fatal("item/category lost")
	}
}
