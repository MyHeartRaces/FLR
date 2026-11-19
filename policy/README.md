# Routing policy

The image ships a neutral policy: local destinations (LAN, private ranges,
`.lan`/`.local` names) stay local and **everything else goes through the
VPN**. No routing lists are part of this repository or the public image.

## Private overlay

An owner can install a private policy on the router at
`/etc/flr-runtime/policy/` with the same layout:

```
policy.json                 {"format":"flint2-home-vpn-routing-policy","version":3,"default_class":"vpn-general"}
rulesets/local-domains.json
rulesets/local-ips.json
rulesets/vpn-required.json         domains/CIDRs that must use the VPN (wins over direct lists)
rulesets/direct-essential.json     services that must go direct (banks, government)
rulesets/game-platforms.json       game platforms, carried by the Games class
rulesets/vpn-services.json         services pinned to the VPN
rulesets/roscom-direct-domains.json  broad direct domains (used only in routing mode "split")
rulesets/roscom-direct-ips.json      broad direct CIDRs (used only in routing mode "split")
```

Each ruleset is `{"version":3,"rules":[{"domain":[…],"domain_suffix":[…],
"domain_keyword":[…],"domain_regex":[…],"ip_cidr":[…]}]}`.

The controller uses the overlay when it loads cleanly and otherwise falls
back to the image policy (all traffic through the VPN) and reports the
overlay error. `/etc/flr-runtime/` is kept across sysupgrade.

## Managing it from LuCI

«FLR → Routing» shows which policy is in use, counts and pages through every
ruleset, and holds the owner's **custom rules** (domains, IPv4 addresses,
subnets and ranges sent through the VPN or directly through the ISP), stored
only on the router in `/etc/flr-runtime/custom-rules.json`. Custom rules take
precedence over the rulesets except local destinations. The same page exports
the effective configuration (policy, rulesets and custom rules) as one JSON
file, imports such a file as the overlay (the previous overlay is kept as
`/etc/flr-runtime/policy.backup`), and resets to the image default. Changes
apply to new connections without restarting the VPN. API and file formats:
`docs/ROUTER-API.md`, "Routing policy API".

## RoscomVPN profiles

The same page can build the overlay from a RoscomVPN routing profile (Happ or
INCY JSON, an edited copy, or its routing link): presets for the published
Whitelist and Default profiles, an HTTPS URL or a file. The router downloads
the geosite and geoip files the profile names (through the VPN while it
runs), converts DirectSites/DirectIp into the broad direct lists,
ProxySites/ProxyIp into VPN lists and private categories into local
destinations, and installs the result like an import: the previous overlay
becomes the backup, custom rules stay. Preview shows the conversion report
without changing anything. It never runs on its own. Mapping, skipped
entries, download path and limits: `docs/ROUTER-API.md`, "RoscomVPN import".
