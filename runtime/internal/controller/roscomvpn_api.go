package controller

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/MyHeartRaces/FLR/runtime/internal/contract"
	"github.com/MyHeartRaces/FLR/runtime/internal/control"
	dnsbroker "github.com/MyHeartRaces/FLR/runtime/internal/dns"
	"github.com/MyHeartRaces/FLR/runtime/internal/geodata"
	"github.com/MyHeartRaces/FLR/runtime/internal/policy"
	"github.com/MyHeartRaces/FLR/runtime/internal/privatefile"
	"github.com/MyHeartRaces/FLR/runtime/internal/socks"
)

// RoscomVPN import (docs/ROUTER-API.md, "RoscomVPN import"): the operation
// routing-roscomvpn-import reads a Happ/INCY routing profile (HTTPS URL or a
// file staged with routing-import-begin/chunk), downloads the geosite.dat and
// geoip.dat it names, converts it (geodata.Convert) and installs the result
// exactly like a bundle import: stage, load-check, keep the previous overlay
// as the backup, apply live. dry_run converts and reports without changing
// anything. It runs only when the owner starts it; nothing at start or
// upgrade calls it.
//
// With the controller running the work is a background job: downloads and
// the conversion run without adminMu, so controller rounds (health,
// failover, routing reconcile) are never held up by the network; only the
// final install takes adminMu, for as long as a bundle import does.
// routing-roscomvpn-status reports the job. Without a running controller
// (offline CLI) the import runs within the request.

const (
	roscomProfileTimeout = 20 * time.Second
	roscomDataTimeout    = 90 * time.Second
	roscomJobTimeout     = 4 * time.Minute
	// roscomDataLimit bounds one geosite.dat or geoip.dat download. The
	// RoscomVPN files measured 2026-11-19 are 68 KB and 440 KB; the full
	// community files are a few MiB.
	roscomDataLimit = 32 << 20
)

// routingFetcher downloads an HTTPS URL over route, refusing bodies above
// limit. Tests replace it.
type routingFetcher func(ctx context.Context, route downloadRoute, rawURL string, limit int64) ([]byte, error)

// downloadRoute is the egress path of the import downloads: the active VPN
// channel while the VPN runs, otherwise the WAN.
type downloadRoute struct {
	Path string `json:"path"` // vpn-awg, vpn-gecko, vpn-vless or wan
	WAN  string `json:"-"`
}

type roscomJob struct {
	ID       string         `json:"id"`
	Pending  bool           `json:"pending"`
	Phase    string         `json:"phase"`
	DryRun   bool           `json:"dry_run"`
	Started  time.Time      `json:"started"`
	Finished *time.Time     `json:"finished,omitempty"`
	Error    string         `json:"error,omitempty"`
	Result   map[string]any `json:"result,omitempty"`
}

// roscomRequest is what the job needs, captured under adminMu.
type roscomRequest struct {
	URL          string
	Profile      []byte
	DryRun       bool
	Route        downloadRoute
	LocalDomains []policy.Entry
	LocalIPs     []policy.Entry
}

func (c *Controller) setRoscomPhase(job *roscomJob, phase string) {
	c.mu.Lock()
	job.Phase = phase
	c.mu.Unlock()
}

// roscomRoute picks the download path. While the VPN runs the downloads go
// through its active channel only (no silent WAN fallback): the CDN hosts
// of the published profiles are often unreachable from Russian ISPs, and the
// ISP should not see the request. Without a running VPN (first setup, VPN
// off, offline CLI) they go through the WAN like a subscription download.
func (c *Controller) roscomRoute() (downloadRoute, error) {
	c.mu.RLock()
	running, general := c.live && c.vpnStarted, c.selection.General
	c.mu.RUnlock()
	route := downloadRoute{Path: "wan", WAN: c.settings.Options.WAN}
	if !running {
		return route, nil
	}
	switch general {
	case contract.AWG:
		route.Path = "vpn-awg"
	case contract.Gecko:
		route.Path = "vpn-gecko"
	case contract.VLESS:
		route.Path = "vpn-vless"
	default:
		return route, fmt.Errorf("the VPN runs but no channel is up; retry when a channel is healthy")
	}
	return route, nil
}

func (c *Controller) roscomStatus() (any, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.roscom == nil {
		return map[string]any{"job": nil}, nil
	}
	job := *c.roscom
	return map[string]any{"job": job}, nil
}

// roscomImport starts an import. Callers hold adminMu.
func (c *Controller) roscomImport(args routingArgs) (any, error) {
	if (args.URL == "") == (args.Staging == "") {
		return nil, fmt.Errorf("the import needs exactly one of url or staging_id")
	}
	if !args.DryRun && !args.Accepted {
		return nil, fmt.Errorf("explicit confirmation required: the import replaces the routing policy")
	}
	if args.Offset != 0 || args.Size != 0 || args.SHA256 != "" || args.Data != "" || args.Rule != nil || args.Ruleset != "" || args.Query != "" || args.ID != "" || args.Revision != "" || args.Limit != 0 {
		return nil, fmt.Errorf("unexpected routing argument")
	}
	c.mu.RLock()
	busy := c.roscom != nil && c.roscom.Pending
	c.mu.RUnlock()
	if busy {
		return nil, fmt.Errorf("a RoscomVPN import is already running")
	}
	req := roscomRequest{URL: args.URL, DryRun: args.DryRun}
	if args.URL != "" {
		if _, err := downloadURL(args.URL); err != nil {
			return nil, err
		}
	} else {
		raw, err := takeStaged(args.Staging, geodata.MaxProfileBytes)
		if err != nil {
			return nil, err
		}
		req.Profile = raw
	}
	var err error
	if req.Route, err = c.roscomRoute(); err != nil {
		return nil, err
	}
	// The overlay keeps the image's local destinations.
	if req.LocalDomains, err = policy.RulesetEntries(routingImageDir, "local-domains"); err != nil {
		return nil, fmt.Errorf("image policy unreadable: %v", err)
	}
	if req.LocalIPs, err = policy.RulesetEntries(routingImageDir, "local-ips"); err != nil {
		return nil, fmt.Errorf("image policy unreadable: %v", err)
	}
	var random [8]byte
	if _, err = rand.Read(random[:]); err != nil {
		return nil, fmt.Errorf("import unavailable")
	}
	job := &roscomJob{ID: hex.EncodeToString(random[:]), Pending: true, Phase: "queued", DryRun: req.DryRun, Started: time.Now().UTC()}
	c.mu.Lock()
	c.roscom = job
	c.mu.Unlock()
	if c.live && c.ctx != nil {
		parent := c.ctx
		c.testWorkers.Add(1)
		go func() {
			defer c.testWorkers.Done()
			ctx, cancel := context.WithTimeout(parent, roscomJobTimeout)
			defer cancel()
			result, err := c.runRoscom(ctx, job, req, false)
			c.finishRoscom(job, result, err)
		}()
		return map[string]any{"pending": true, "job": job.ID, "dry_run": req.DryRun, "download_path": req.Route.Path}, nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), roscomJobTimeout)
	defer cancel()
	result, err := c.runRoscom(ctx, job, req, true)
	c.finishRoscom(job, result, err)
	if err != nil {
		return nil, err
	}
	result["pending"], result["job"] = false, job.ID
	return result, nil
}

func (c *Controller) finishRoscom(job *roscomJob, result map[string]any, err error) {
	now := time.Now().UTC()
	c.mu.Lock()
	job.Pending, job.Finished, job.Result = false, &now, result
	if err != nil {
		job.Phase, job.Error = "failed", err.Error()
	} else {
		job.Phase = "done"
	}
	c.mu.Unlock()
}

// takeStaged reads and drops a complete staged upload.
func takeStaged(id string, limit int) ([]byte, error) {
	meta, size, err := staged(id)
	if err != nil {
		return nil, err
	}
	defer removeStaging(id)
	if size != meta.Size {
		return nil, fmt.Errorf("upload incomplete: %d of %d bytes received", size, meta.Size)
	}
	if meta.Size > int64(limit) {
		return nil, fmt.Errorf("the profile is larger than %d bytes", limit)
	}
	_, partPath := stagingPaths(id)
	raw, err := privatefile.Read(partPath, limit)
	if err != nil {
		return nil, fmt.Errorf("upload unreadable")
	}
	if sum := sha256.Sum256(raw); hex.EncodeToString(sum[:]) != meta.SHA256 {
		return nil, fmt.Errorf("upload checksum mismatch; start it again")
	}
	return raw, nil
}

func sinceMS(t time.Time) int64 { return time.Since(t).Milliseconds() }

// runRoscom downloads, converts and (unless a dry run) installs. locked says
// whether the caller already holds adminMu and the admin file lock.
func (c *Controller) runRoscom(ctx context.Context, job *roscomJob, req roscomRequest, locked bool) (map[string]any, error) {
	started := time.Now()
	timings := map[string]int64{}
	fetch := c.routingFetch
	if fetch == nil {
		fetch = fetchHTTPS
	}
	download := func(what, rawURL string, limit int64, timeout time.Duration) ([]byte, error) {
		c.setRoscomPhase(job, "downloading "+what)
		t := time.Now()
		dctx, cancel := context.WithTimeout(ctx, timeout)
		defer cancel()
		data, err := fetch(dctx, req.Route, rawURL, limit)
		timings[what+"_ms"] = sinceMS(t)
		if err != nil {
			return nil, fmt.Errorf("%s download failed (%s): %v", what, req.Route.Path, err)
		}
		return data, nil
	}
	// Published provenance never carries a query, user information or
	// fragment (they may hold tokens): scheme, host and path, plus the
	// SHA-256 of what was read. Full URLs are used only to fetch.
	source := "uploaded file"
	raw := req.Profile
	if req.URL != "" {
		source = geodata.SourceURL(req.URL)
		var err error
		if raw, err = download("profile", req.URL, geodata.MaxProfileBytes, roscomProfileTimeout); err != nil {
			return nil, err
		}
	}
	profileSum := sha256.Sum256(raw)
	body, err := geodata.ProfileJSON(raw)
	if err != nil {
		return nil, err
	}
	if err = control.CheckJSON(body); err != nil {
		return nil, fmt.Errorf("profile rejected: %v", err)
	}
	profile, err := geodata.ParseProfile(body)
	if err != nil {
		return nil, fmt.Errorf("profile rejected: %v", err)
	}
	in := geodata.Input{Profile: profile, ProfileSource: source, ProfileSHA256: hex.EncodeToString(profileSum[:]), LocalDomains: req.LocalDomains, LocalIPs: req.LocalIPs}
	needSites, needIPs := profile.Needs()
	data := map[string]any{}
	if needSites {
		if profile.GeositeURL == "" {
			return nil, fmt.Errorf("the profile uses geosite categories but names no Geositeurl")
		}
		b, err := download("geosite", profile.GeositeURL, roscomDataLimit, roscomDataTimeout)
		if err != nil {
			return nil, err
		}
		if in.Sites, err = geodata.ParseSites(ctx, b); err != nil {
			return nil, err
		}
		sum := sha256.Sum256(b)
		in.GeositeSource, in.GeositeSHA256 = geodata.SourceURL(profile.GeositeURL), hex.EncodeToString(sum[:])
		data["geosite"] = map[string]any{"url": in.GeositeSource, "bytes": len(b), "sha256": in.GeositeSHA256, "categories": in.Sites.Len()}
	}
	if needIPs {
		if profile.GeoipURL == "" {
			return nil, fmt.Errorf("the profile uses geoip categories but names no Geoipurl")
		}
		b, err := download("geoip", profile.GeoipURL, roscomDataLimit, roscomDataTimeout)
		if err != nil {
			return nil, err
		}
		if in.IPs, err = geodata.ParseIPs(ctx, b); err != nil {
			return nil, err
		}
		sum := sha256.Sum256(b)
		in.GeoipSource, in.GeoipSHA256 = geodata.SourceURL(profile.GeoipURL), hex.EncodeToString(sum[:])
		data["geoip"] = map[string]any{"url": in.GeoipSource, "bytes": len(b), "sha256": in.GeoipSHA256, "categories": in.IPs.Len()}
	}
	c.setRoscomPhase(job, "converting")
	t := time.Now()
	in.ImportedAt = time.Now().UTC()
	overlay, err := geodata.Convert(ctx, in)
	if err != nil {
		return nil, err
	}
	bundle := &routingBundle{Format: routingBundleFormat, Version: routingBundleVersion, Source: "overlay", Policy: overlay.Policy, Rulesets: overlay.Rulesets}
	// The overlay must stay exportable with the largest custom rules list.
	exported, err := json.MarshalIndent(bundle, "", " ")
	if err != nil {
		return nil, err
	}
	if len(exported)+maxCustomRulesBytes > maxRoutingBundle {
		return nil, fmt.Errorf("the converted policy (%d bytes) exceeds the routing bundle limit; use a smaller profile", len(exported))
	}
	timings["convert_ms"] = sinceMS(t)
	result := map[string]any{"dry_run": req.DryRun, "installed": false, "download_path": req.Route.Path, "source": source, "source_sha256": in.ProfileSHA256, "data": data, "report": overlay.Report, "timings": timings}
	if req.DryRun {
		timings["total_ms"] = sinceMS(started)
		return result, nil
	}
	c.setRoscomPhase(job, "installing")
	t = time.Now()
	if !locked {
		c.adminMu.Lock()
		defer c.adminMu.Unlock()
		if ctx.Err() != nil || (c.ctx != nil && c.ctx.Err() != nil) || !c.live {
			return nil, fmt.Errorf("controller stopping; nothing was installed")
		}
		lock, err := lockPrivateAdmin(c.stateDir)
		if err != nil {
			return nil, err
		}
		defer lock.Close()
	}
	apply, err := c.installRoutingPolicy(bundle)
	if err != nil {
		return nil, err
	}
	timings["install_ms"] = sinceMS(t)
	timings["total_ms"] = sinceMS(started)
	result["installed"], result["apply"] = true, apply
	result["backup_present"] = exists(filepath.Join(c.overlayBackupDir(), "policy.json"))
	return result, nil
}

// installRoutingPolicy stages, load-checks and installs a policy bundle
// (custom rules untouched) and applies it. Callers hold adminMu.
func (c *Controller) installRoutingPolicy(bundle *routingBundle) (routingApply, error) {
	candidate, err := c.stageOverlay(bundle)
	if err != nil {
		return routingApply{}, err
	}
	defer os.RemoveAll(candidate)
	_, keep, err := c.installOverlay(candidate)
	if err != nil {
		return routingApply{}, err
	}
	keep()
	apply, err := c.applyRouting()
	if err != nil {
		return routingApply{}, fmt.Errorf("policy installed, but not applied: %v", err)
	}
	return apply, nil
}

// downloadURL accepts an HTTPS URL on port 443 without credentials.
func downloadURL(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || len(raw) > 8192 || (u.Port() != "" && u.Port() != "443") || strings.ContainsAny(raw, "\r\n\x00 ") {
		return nil, fmt.Errorf("the URL must be HTTPS on port 443 without credentials")
	}
	return u, nil
}

// fetchHTTPS downloads rawURL through route. Every redirect must again be
// HTTPS on port 443 (at most 5); TLS verifies the URL host; addresses must be
// public IPv4.
func fetchHTTPS(ctx context.Context, route downloadRoute, rawURL string, limit int64) ([]byte, error) {
	if _, err := downloadURL(rawURL); err != nil {
		return nil, err
	}
	dial, err := routeDialer(route)
	if err != nil {
		return nil, err
	}
	transport := &http.Transport{Proxy: nil, DisableKeepAlives: true, TLSHandshakeTimeout: 15 * time.Second, ResponseHeaderTimeout: 20 * time.Second, MaxResponseHeaderBytes: 32 << 10}
	transport.DialContext = func(ctx context.Context, _, address string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(address)
		if err != nil || port != "443" {
			return nil, fmt.Errorf("invalid download endpoint")
		}
		if ip := net.ParseIP(host); ip != nil && !publicIP(ip) {
			return nil, fmt.Errorf("download destination is not public IPv4")
		}
		return dial(ctx, host, port)
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, CheckRedirect: func(r *http.Request, via []*http.Request) error {
		if len(via) > 5 {
			return fmt.Errorf("too many redirects")
		}
		_, err := downloadURL(r.URL.String())
		return err
	}}
	request, err := http.NewRequestWithContext(ctx, "GET", rawURL, nil)
	if err != nil {
		return nil, fmt.Errorf("request failed")
	}
	request.Header.Set("User-Agent", "flr-controller")
	response, err := client.Do(request)
	if err != nil {
		// Without the URL: a profile URL may carry a private token.
		var ue *url.Error
		if errors.As(err, &ue) {
			return nil, fmt.Errorf("%s", ue.Err)
		}
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP status %d", response.StatusCode)
	}
	if response.ContentLength > limit {
		return nil, fmt.Errorf("larger than %d bytes", limit)
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, limit+1))
	if err != nil {
		return nil, fmt.Errorf("read failed: %v", err)
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("larger than %d bytes", limit)
	}
	return data, nil
}

// socksDial and socksProxies reach the proxy channels' local SOCKS
// listeners (replaced in tests).
var (
	socksDial    = socks.DialContext
	socksProxies = map[string]string{"vpn-gecko": "127.0.0.1:1081", "vpn-vless": "127.0.0.1:1082"}
)

// tunnelDNS is the resolver the downloads use inside the tunnel.
const tunnelDNS = "1.1.1.1:53"

// routeDialer returns a TCP dialer to host:port over the route, the way the
// engine updater reaches the internet through the tunnel. Every path
// resolves the name itself through that same path and connects only to a
// validated public IPv4 address; the hostname stays with the HTTP client
// for TLS SNI and certificate checks. That holds for redirects too, since
// every connection goes through this dialer.
//   - vpn-awg: DNS (UDP) and TCP bound to flr_awg with the AWG channel mark;
//   - vpn-gecko, vpn-vless: DNS over TCP to the tunnel resolver through the
//     channel's local SOCKS listener, then a SOCKS CONNECT to the numeric
//     address (a hostname is never handed to SOCKS, so the server side
//     cannot be made to reach its own loopback or private networks);
//   - wan: the subscription fetcher's resolver (1.1.1.1 over the WAN, outer
//     mark).
func routeDialer(route downloadRoute) (func(ctx context.Context, host, port string) (net.Conn, error), error) {
	var lookup func(ctx context.Context, host string) ([]net.IP, error)
	var dial func(ctx context.Context, address string) (net.Conn, error)
	switch route.Path {
	case "vpn-awg":
		mark := contract.ChannelMark(contract.AWG) | contract.ClassMark(contract.General) | contract.ProbeMark
		resolver := &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return dnsbroker.DialMarked(ctx, network, tunnelDNS, contract.ChannelMark(contract.AWG)|contract.ProbeMark, "flr_awg")
		}}
		lookup = func(ctx context.Context, host string) ([]net.IP, error) { return resolver.LookupIP(ctx, "ip4", host) }
		dial = func(ctx context.Context, address string) (net.Conn, error) {
			return dnsbroker.DialMarked(ctx, "tcp", address, mark, "flr_awg")
		}
	case "vpn-gecko", "vpn-vless":
		proxy := socksProxies[route.Path]
		// A stream connection makes the Go resolver use DNS over TCP.
		resolver := &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return socksDial(ctx, proxy, tunnelDNS)
		}}
		lookup = func(ctx context.Context, host string) ([]net.IP, error) { return resolver.LookupIP(ctx, "ip4", host) }
		dial = func(ctx context.Context, address string) (net.Conn, error) { return socksDial(ctx, proxy, address) }
	case "wan":
		f := Fetcher{WAN: route.WAN}
		lookup = f.resolve
		dial = func(ctx context.Context, address string) (net.Conn, error) {
			return dnsbroker.DialMarked(ctx, "tcp", address, contract.OuterMark, route.WAN)
		}
	default:
		return nil, fmt.Errorf("no download route")
	}
	return func(ctx context.Context, host, port string) (net.Conn, error) {
		ip := net.ParseIP(host)
		if ip == nil {
			ips, err := lookup(ctx, host)
			if err != nil || len(ips) == 0 {
				return nil, fmt.Errorf("DNS for the download failed (%s)", route.Path)
			}
			ip = ips[0]
		}
		if ip = ip.To4(); ip == nil || !publicIP(ip) {
			return nil, fmt.Errorf("download destination is not a public IPv4 address")
		}
		return dial(ctx, net.JoinHostPort(ip.String(), port))
	}, nil
}
