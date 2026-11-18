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
