package connection

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

const testURI = "hysteria2://PUBLIC_TEST_PASSWORD@192.0.2.10:443/?obfs=salamander&obfs-password=PUBLIC_TEST_OBFS&sni=example.com"
const testKey = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE="

func testAWG(endpoint string) string {
	return "[Interface]\nPrivateKey = " + testKey + "\nHeaderProtectionKey = " + testKey + "\nAddress = 10.77.0.2/32\nS1 = 12\nS2 = 12\nS3 = 12\nS4 = 12\nTable = off\n[Peer]\nPublicKey = " + testKey + "\nPresharedKey = " + testKey + "\nEndpoint = " + endpoint + "\nAllowedIPs = 0.0.0.0/0\n"
}
func testConnection(t *testing.T, raw string) Connection {
	t.Helper()
	items, err := ParseImport([]byte(raw))
	if err != nil || len(items) != 1 {
		t.Fatalf("connection import: %v", err)
	}
	return items[0]
}
func TestConnectionStableIDAndRevision(t *testing.T) {
	c := testConnection(t, testURI)
	c.Name, c.Group = "My Main", "Main"
	r := &Registry{Version: 2, Connections: []Connection{c}}
	if err := r.Replace(c.ID, []byte(strings.Replace(testURI, "192.0.2.10", "192.0.2.20", 1))); err != nil {
		t.Fatal(err)
	}
	updated := r.Connections[0]
	if updated.ID != c.ID || updated.Name != c.Name || updated.Group != c.Group || updated.Enabled != c.Enabled || updated.Revision == c.Revision {
		t.Fatal("replacement lost logical identity or retained old config revision")
	}
	if err := ValidateRegistry(r); err != nil {
		t.Fatal(err)
	}
	before, _ := json.Marshal(r)
	if err := r.Replace(c.ID, []byte("invalid")); err == nil {
		t.Fatal("invalid replacement accepted")
	}
	after, _ := json.Marshal(r)
	if string(before) != string(after) {
		t.Fatal("invalid replacement mutated registry")
	}
}
func TestConnectionImportAtomicMixedAndDuplicate(t *testing.T) {
	r := &Registry{Version: 2}
	batch, _ := json.Marshal([]string{testURI, testAWG("192.0.2.30:51820")})
	if _, err := r.Import(batch); err != nil || len(r.Connections) != 2 {
		t.Fatal("proxy/AWG batch rejected", err)
	}
	if r.Connections[0].Family != "hy2" || r.Connections[1].Family != "awg" {
		t.Fatal("wrong families in mixed batch")
	}
	before, _ := json.Marshal(r)
	if _, err := r.Import([]byte(testURI)); err == nil || !strings.Contains(err.Error(), r.Connections[0].ID) {
		t.Fatal("duplicate import did not identify existing connection")
	}
	bad, _ := json.Marshal([]string{strings.Replace(testURI, "192.0.2.10", "192.0.2.40", 1), "[Interface]\nPrivateKey = bad"})
	if _, err := r.Import(bad); err == nil {
		t.Fatal("partial invalid batch accepted")
	}
	after, _ := json.Marshal(r)
	if string(before) != string(after) {
		t.Fatal("failed batch changed stored connections")
	}
}
func TestConnectionPrivateStoreAndSecrets(t *testing.T) {
	for _, raw := range []string{testURI, testAWG("192.0.2.30:51820")} {
		c := testConnection(t, raw)
		secret := "PUBLIC_TEST_PASSWORD"
		if c.Family == "awg" {
			secret = testKey
		}
		c.Name, c.Group = "name-"+secret, "vps-"+secret
		encoded, _ := json.Marshal(c.Summary())
		if strings.Contains(string(encoded), secret) || strings.Contains(string(encoded), "private_key") || strings.Contains(string(encoded), "PrivateKey") {
			t.Fatal("connection summary exposed credentials")
		}
		r := &Registry{Version: 2, Connections: []Connection{c}}
		path := filepath.Join(t.TempDir(), "private", "registry.json")
		if err := r.Save(path); err != nil {
			t.Fatal(err)
		}
		stored, err := Load(path)
		if err != nil || stored.Connections[0].ID != c.ID || stored.Connections[0].Name != c.Name {
			t.Fatal("private round trip lost credentials or logical metadata", err)
		}
		info, _ := os.Stat(path)
		dir, _ := os.Stat(filepath.Dir(path))
		if info.Mode().Perm() != 0600 || dir.Mode().Perm() != 0700 {
			t.Fatal("connection registry is not private")
		}
		if err = os.Remove(path); err != nil {
			t.Fatal(err)
		}
		if err = os.Symlink(filepath.Join(t.TempDir(), "target"), path); err != nil {
			t.Fatal(err)
		}
		if err = r.Save(path); err == nil {
			t.Fatal("registry followed symlink target")
		}
	}
}
func TestConnectionRegistryCapacityAndTampering(t *testing.T) {
	c := testConnection(t, testURI)
	r := &Registry{Version: 2}
	for i := 0; i < 64; i++ {
		copy := c
		copy.ID = "conn-" + strings.Repeat("a", i+1)
		r.Connections = append(r.Connections, copy)
	}
	if err := ValidateRegistry(r); err == nil {
		t.Fatal("duplicate payloads accepted under different logical IDs")
	}
	r.Connections = []Connection{c}
	r.Connections[0].Revision = strings.Repeat("0", 64)
	if err := ValidateRegistry(r); err == nil {
		t.Fatal("forged revision accepted")
	}
	c.AWG = map[string]string{"PrivateKey": testKey}
	r.Connections = []Connection{c}
	if err := ValidateRegistry(r); err == nil {
		t.Fatal("two payload types accepted")
	}
}
func TestConnectionCapacityRejectsSixtyFifthWithoutMutation(t *testing.T) {
	r := &Registry{Version: 2}
	for i := 1; i <= 64; i++ {
		input := strings.Replace(testURI, "192.0.2.10", "192.0.2."+strconv.Itoa(i), 1)
		if _, err := r.Import([]byte(input)); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := r.Import([]byte(strings.Replace(testURI, "192.0.2.10", "192.0.2.65", 1))); err == nil || len(r.Connections) != 64 {
		t.Fatal("sixty-fifth connection accepted or registry mutated")
	}
}

func TestConnectionAWGImportAcceptsLeadingComments(t *testing.T) {
	input := "# Public AWG test configuration\n; exported configuration\n\n" + testAWG("192.0.2.30:51820")
	items, err := ParseImport([]byte(input))
	if err != nil || len(items) != 1 || items[0].Family != "awg" {
		t.Fatal("valid AWG file comments rejected", err)
	}
}

func TestConnectionReplacementDoesNotExposePreviousCredentialLabels(t *testing.T) {
	c := testConnection(t, testURI)
	c.Name, c.Group = "name-PUBLIC_TEST_PASSWORD", "vps-PUBLIC_TEST_OBFS"
	r := &Registry{Version: 2, Connections: []Connection{c}}
	raw := strings.ReplaceAll(strings.ReplaceAll(testURI, "PUBLIC_TEST_PASSWORD", "PUBLIC_NEW_PASSWORD"), "PUBLIC_TEST_OBFS", "PUBLIC_NEW_OBFS")
	if err := r.Replace(c.ID, []byte(raw)); err != nil {
		t.Fatal(err)
	}
	encoded, _ := json.Marshal(r.Summaries())
	if strings.Contains(string(encoded), "PUBLIC_TEST_PASSWORD") || strings.Contains(string(encoded), "PUBLIC_TEST_OBFS") {
		t.Fatal("replacement exposed credential-bearing labels from old payload")
	}
}
