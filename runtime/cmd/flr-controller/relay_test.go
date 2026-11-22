package main

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/MyHeartRaces/FLR/runtime/internal/connection"
	"github.com/MyHeartRaces/FLR/runtime/internal/profile"
)

func TestRelayAttemptValidatesBuildIdentityDeadlineAndCandidatePort(t *testing.T) {
	now := time.Unix(100, 0).UTC()
	build := strings.Repeat("a", 40)
	valid := string(`{"format":"flr-relay-attempt-v1","nonce":"` + strings.Repeat("b", 64) + `","router_build":"` + build + `","candidate_sha256":"` + strings.Repeat("c", 64) + `","profile_revision":"` + strings.Repeat("d", 64) + `","relay_id":"relay-a","listener":"candidate","address":"203.0.113.9","port":24443,"expires_at":"` + now.Add(time.Minute).Format(time.RFC3339) + `"}`)
	if attempt, err := readRelayAttempt(strings.NewReader(valid), now, build, "relay-a", 24443); err != nil || attempt.Port != 24443 {
		t.Fatalf("valid attempt refused: %+v %v", attempt, err)
	}
	for name, bad := range map[string]string{
		"build":   strings.Replace(valid, build, strings.Repeat("e", 40), 1),
		"relay":   strings.Replace(valid, "relay-a", "relay-b", 1),
		"port":    strings.Replace(valid, "24443", "24444", 1),
		"stale":   strings.Replace(valid, now.Add(time.Minute).Format(time.RFC3339), now.Format(time.RFC3339), 1),
		"extra":   valid + `{}`,
		"address": strings.Replace(valid, "203.0.113.9", "127.0.0.1", 1),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := readRelayAttempt(strings.NewReader(bad), now, build, "relay-a", 24443); err == nil {
				t.Fatal("expected rejection")
			}
		})
	}
}

func TestRelayTargetPinsPortAndPreservesTLS(t *testing.T) {
	profiles, err := profile.Parse([]byte("hy2://PUBLIC_TEST_PASSWORD@relay.example.com:443?obfs=salamander&obfs-password=PUBLIC_TEST_OBFS#test"))
	if err != nil || len(profiles) != 1 {
		t.Fatal(err)
	}
	p := profiles[0]
	c := connection.Connection{ID: "conn-test", Family: "hy2", Enabled: true, Revision: strings.Repeat("d", 64), Profile: &p}
	a := relayAttempt{ProfileRevision: c.Revision, Listener: "candidate", Address: "203.0.113.9", Port: 24443}
	target, host, err := renderRelayTarget(c, a, "eth1", t.TempDir())
	if err != nil || host != "relay.example.com" || target.Server != a.Address || !target.UDP {
		t.Fatalf("unexpected canary target: %s %v", host, err)
	}
	var rendered struct{ Outbounds []map[string]any }
	if err := json.Unmarshal(target.Config, &rendered); err != nil || len(rendered.Outbounds) != 1 {
		t.Fatal("expected one native Hysteria2 outbound")
	}
	o := rendered.Outbounds[0]
	tls, _ := o["tls"].(map[string]any)
	if o["server"] != a.Address || o["server_port"] != float64(24443) || o["bind_interface"] != "eth1" || tls["server_name"] != host || p.Outbound["server"] != host {
		t.Fatal("canary target changed TLS, WAN binding, or the saved profile")
	}
	a.Listener = "production"
	if _, _, err := renderRelayTarget(c, a, "eth1", t.TempDir()); err == nil {
		t.Fatal("production port override accepted")
	}
}
