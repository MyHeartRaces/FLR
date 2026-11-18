package dataplane

import (
	"strings"
	"testing"

	"github.com/MyHeartRaces/FLR/runtime/internal/policy"
)

func TestStaticSetsBatchFollowsRoutingMode(t *testing.T) {
	p, e := policy.Load("../policy/testdata/split")
	if e != nil {
		t.Fatal(e)
	}
	split := StaticSetsBatch(p)
	full := StaticSetsBatch(p.ForMode(policy.ModeFull))
	for _, want := range []string{"flush set inet flr local4\n", "flush set inet flr broad_direct4\n", "flush set inet flr service_static4\n", "add element inet flr service_static4 { 17.0.0.0/8 }"} {
		if !strings.Contains(split, want) || !strings.Contains(full, want) {
			t.Fatalf("missing %q", want)
		}
	}
	if !strings.Contains(split, "add element inet flr broad_direct4 { 5.255.255.0/24 }") || strings.Contains(full, "add element inet flr broad_direct4") {
		t.Fatalf("broad direct set does not follow the mode:\n%s\n%s", split, full)
	}
	if strings.Contains(split, "delete table") || strings.Contains(split, "flush ruleset") {
		t.Fatal("static set update must not replace the table")
	}
}
