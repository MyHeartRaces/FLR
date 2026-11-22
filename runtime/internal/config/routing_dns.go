package config

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"

	"github.com/MyHeartRaces/FLR/runtime/internal/native"
	"github.com/MyHeartRaces/FLR/runtime/internal/privatefile"
)

const policyDNSMasqPort = "1053"

var routingDNSKeys = []string{"port", "noresolv", "server"}

type dnsmasqOption struct {
	list   bool
	values []string
}

type dnsmasqRoutingSettings struct {
	section string
	options map[string]dnsmasqOption
}

// SetRoutingDNS switches the first dnsmasq instance between the native settings
// backed up at activation and the local-only resolver used by the policy broker.
// Callers must release the broker's port 53 before switching to native DNS.
func SetRoutingDNS(direct bool) error {
	return setRoutingDNS(direct, "/etc/config/dhcp", "/etc/flr-runtime/backup/dhcp", "/etc/flr-runtime/dnsmasq-restart.pending", native.Output)
}

// CheckNativeRoutingDNS validates the handoff while the current resolver can
// still serve. SetRoutingDNS repeats the checks before committing.
func CheckNativeRoutingDNS() error {
	return routingDNS(true, true, "/etc/config/dhcp", "/etc/flr-runtime/backup/dhcp", "/etc/flr-runtime/dnsmasq-restart.pending", native.Output)
}

func setRoutingDNS(direct bool, dhcp, backup, pending string, command func(string, ...string) ([]byte, error)) error {
	return routingDNS(direct, false, dhcp, backup, pending, command)
}

func routingDNS(direct, checkOnly bool, dhcp, backup, pending string, command func(string, ...string) ([]byte, error)) error {
	// The uci CLI retains its default delta search path even with a custom
	// savedir. Unique package aliases keep dhcp's staged changes out of the
	// commit. UCI resolves the alias symlink when committing to its target.
	dir, err := os.MkdirTemp(filepath.Dir(dhcp), ".flr-dns-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)
	delta := filepath.Join(dir, "delta")
	if err = os.Mkdir(delta, 0700); err != nil {
		return err
	}
	pkg := "flr_dns_" + strings.TrimPrefix(filepath.Base(dir), ".flr-dns-")
	uci := func(verb, arg string) ([]byte, error) {
		return command("uci", "-s", "-N", "-c", dir, "-C", dir, "-t", delta, verb, arg)
	}
	read := func(alias, path string) (dnsmasqRoutingSettings, error) {
		info, e := os.Lstat(path)
		if e != nil || !info.Mode().IsRegular() || info.Size() == 0 {
			return dnsmasqRoutingSettings{}, fmt.Errorf("DHCP configuration unavailable")
		}
		if e = os.Symlink(path, filepath.Join(dir, alias)); e != nil {
			return dnsmasqRoutingSettings{}, e
		}
		data, e := uci("export", alias)
		if e != nil {
			return dnsmasqRoutingSettings{}, e
		}
		return parseDNSMasqRouting(data, alias)
	}
	checkStaged := func() error {
		out, e := command("uci", "-s", "changes", "dhcp")
		if e != nil {
			return fmt.Errorf("cannot check for staged DHCP settings: %w", e)
		}
		if len(bytes.TrimSpace(out)) != 0 {
			return fmt.Errorf("apply or discard staged DHCP settings before switching DNS")
		}
		return nil
	}
	live, err := read(pkg, dhcp)
	if err != nil {
		return fmt.Errorf("cannot read active dnsmasq settings: %w", err)
	}
	policy := dnsmasqRoutingSettings{section: live.section, options: map[string]dnsmasqOption{
		"port": {values: []string{policyDNSMasqPort}}, "noresolv": {values: []string{"1"}},
	}}
	want := policy
	if direct || !reflect.DeepEqual(live, policy) {
		original, e := read(pkg+"_backup", backup)
		if e != nil {
			return fmt.Errorf("cannot read native dnsmasq backup: %w", e)
		}
		if original.section != live.section {
			return fmt.Errorf("the first dnsmasq instance differs from the native backup")
		}
		if port, found := original.options["port"]; found && port.values[0] != "53" {
			return fmt.Errorf("native dnsmasq backup must listen on port 53")
		}
		if !reflect.DeepEqual(live, policy) && !reflect.DeepEqual(live, original) {
			return fmt.Errorf("dnsmasq settings differ from both FLR and the native backup")
		}
		if direct {
			want = original
		}
	}
	_, markErr := os.Stat(pending)
	if markErr != nil && !os.IsNotExist(markErr) {
		return markErr
	}
	changed := !reflect.DeepEqual(live, want)
	if !changed && os.IsNotExist(markErr) {
		return nil
	}
	if err = checkStaged(); err != nil {
		return err
	}
	if checkOnly {
		return nil
	}
	if changed {
		for _, key := range routingDNSKeys {
			old, next := live.options[key], want.options[key]
			if reflect.DeepEqual(old, next) {
				continue
			}
			path := pkg + ".@dnsmasq[0]." + key
			if len(old.values) != 0 && (len(next.values) == 0 || old.list || next.list) {
				if _, err = uci("delete", path); err != nil {
					return fmt.Errorf("cannot remove previous dnsmasq %s: %w", key, err)
				}
			}
			verb := "set"
			if next.list {
				verb = "add_list"
			}
			for _, value := range next.values {
				if _, err = uci(verb, path+"="+value); err != nil {
					return fmt.Errorf("cannot stage dnsmasq %s: %w", key, err)
				}
			}
		}
		current, e := read(pkg+"_current", dhcp)
		if e != nil || !reflect.DeepEqual(current, live) {
			return fmt.Errorf("dnsmasq settings changed while switching DNS")
		}
		if err = checkStaged(); err != nil {
			return err
		}
		// Record the pending restart before committing. An interrupted commit or
		// restart can leave the desired options on disk with the old listener.
		if err = privatefile.Write(pending, []byte("1\n")); err != nil {
			return err
		}
		if _, err = uci("commit", pkg); err != nil {
			return fmt.Errorf("cannot commit dnsmasq settings: %w", err)
		}
		current, e = read(pkg+"_committed", dhcp)
		if e != nil || !reflect.DeepEqual(current, want) {
			return fmt.Errorf("dnsmasq commit could not be verified")
		}
		if err = checkStaged(); err != nil {
			return err
		}
	}
	if _, err = command("/etc/init.d/dnsmasq", "restart"); err != nil {
		return fmt.Errorf("cannot restart dnsmasq: %w", err)
	}
	return os.Remove(pending)
}

func parseDNSMasqRouting(data []byte, pkg string) (dnsmasqRoutingSettings, error) {
	s := dnsmasqRoutingSettings{options: make(map[string]dnsmasqOption)}
	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Split(splitUCIExportRecord)
	if !scanner.Scan() || scanner.Text() != "package "+pkg {
		return s, fmt.Errorf("invalid UCI package export")
	}
	found := false
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if config, ok := strings.CutPrefix(line, "config "); ok {
			if found {
				break
			}
			kind, name, _ := strings.Cut(config, " ")
			if kind == "dnsmasq" {
				found = true
				s.section = name // UCI exports named sections with quotes, and anonymous ones without a name.
			}
			continue
		}
		if !found {
			continue
		}
		kind, fields, _ := strings.Cut(line, " ")
		key, quoted, _ := strings.Cut(fields, " ")
		if key != "port" && key != "noresolv" && key != "server" {
			continue
		}
		list := kind == "list"
		if (kind != "option" && !list) || (list && key != "server") || len(quoted) < 2 || quoted[0] != '\'' || quoted[len(quoted)-1] != '\'' {
			return s, fmt.Errorf("invalid dnsmasq %s option", key)
		}
		value := strings.ReplaceAll(quoted[1:len(quoted)-1], `'\''`, `'`)
		if value == "" || strings.ContainsAny(value, "\x00\r\n") {
			return s, fmt.Errorf("invalid dnsmasq %s value", key)
		}
		previous, present := s.options[key]
		if present && (!list || !previous.list) {
			return s, fmt.Errorf("duplicate dnsmasq %s option", key)
		}
		s.options[key] = dnsmasqOption{list: list, values: append(previous.values, value)}
	}
	if err := scanner.Err(); err != nil {
		return s, err
	}
	if !found {
		return s, fmt.Errorf("no dnsmasq instance found")
	}
	return s, nil
}

// UCI export escapes single quotes and leaves quoted newlines intact.
// Split only outside quoted strings so unrelated multiline options stay opaque.
func splitUCIExportRecord(data []byte, atEOF bool) (int, []byte, error) {
	quoted := false
	for i := 0; i < len(data); i++ {
		switch data[i] {
		case '\'':
			quoted = !quoted
		case '\\':
			if !quoted && i+1 < len(data) && data[i+1] == '\'' {
				i++
			}
		case '\n':
			if !quoted {
				return i + 1, data[:i], nil
			}
		}
	}
	if atEOF && quoted {
		return 0, nil, fmt.Errorf("unterminated UCI export value")
	}
	if atEOF && len(data) != 0 {
		return len(data), data, nil
	}
	return 0, nil, nil
}
