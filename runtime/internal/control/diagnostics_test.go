package control

import "testing"

func TestDiagnosticACLSeparatesSummaryAndExport(t *testing.T) {
	if _, err := ParseAPI([]byte(`{"operation":"diagnostics"}`), false, true); err != nil {
		t.Fatal(err)
	}
	if _, err := ParseAPI([]byte(`{"operation":"diagnostics-export","value":"0"}`), false, true); err == nil {
		t.Fatal("expanded history exposed through read ACL")
	}
	if _, err := ParseAPI([]byte(`{"operation":"diagnostics-export","value":"0"}`), false, false); err != nil {
		t.Fatal(err)
	}
	if _, err := ParseAPI([]byte(`{"operation":"diagnostics","value":"secret"}`), false, true); err == nil {
		t.Fatal("summary accepts smuggled payload")
	}
}
