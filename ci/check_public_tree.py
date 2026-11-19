#!/usr/bin/env python3
"""Refuse private material in the public FLR tree.

FLR is public. Credentials, connection profiles, private routing lists,
DNS filter data and the owner's live hosts belong on the router
(/etc/flr-runtime) or in the owner's private repository, never here.

Runs in CI, from tests/test_public_tree.py and as a git pre-commit hook
(ci/git-hooks/pre-commit; enable with `git config core.hooksPath ci/git-hooks`).
"""
from __future__ import annotations

import argparse
import ipaddress
import json
import re
import subprocess
import sys
from pathlib import Path

SKIPPED_PARTS = {".git", "__pycache__", "out", "dl", ".worktrees"}

# Public resolvers and probe targets the code uses on purpose.
ALLOWED_PUBLIC_IPS = {
    "1.1.1.1", "1.0.0.1",                # Cloudflare DNS
    "8.8.8.8", "8.8.4.4",                # Google DNS (health probes)
    "9.9.9.9", "9.9.9.10", "149.112.112.10", "149.112.112.112",  # Quad9
    "77.88.8.8", "77.88.8.1",            # Yandex DNS (direct DoH)
    "104.16.124.96",                     # Cloudflare probe target
}
# Version numbers that look like addresses.
NOT_ADDRESSES = {"1.14.4.1", "1.0.5.2"}

# Live identifiers of a deployment (domains, host names, server addresses,
# admin user names) must not be listed here: this file is public. Keep them
# one per line in a git-ignored file named by $FLR_PRIVATE_NEEDLES or at
# .private-needles in the checkout; the hook and local runs then refuse them.
def blocked_needles(root: Path) -> tuple[str, ...]:
    import os
    path = os.environ.get("FLR_PRIVATE_NEEDLES") or str(root / ".private-needles")
    try:
        lines = Path(path).read_text(encoding="utf-8").splitlines()
    except OSError:
        return ()
    return tuple(l.strip() for l in lines if l.strip() and not l.lstrip().startswith("#"))

SECRET_PATTERNS = {
    "GitHub token": re.compile(r"\b(?:ghp_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|gho_[A-Za-z0-9]{20,})\b"),
    "Telegram bot token": re.compile(r"\b[0-9]{8,10}:[A-Za-z0-9_-]{30,}\b"),
    "AWS access key": re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    "Cloudflare API token": re.compile(r"\bCF_API_TOKEN\s*=\s*['\"]?[A-Za-z0-9_-]{30,}"),
    "private key": re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |ENCRYPTED )?PRIVATE KEY-----\s*[A-Za-z0-9+/=]{40,}"),
    "WireGuard/AWG private key": re.compile(r"(?im)^\s*PrivateKey\s*=\s*[A-Za-z0-9+/]{42,43}=\s*$"),
}
CREDENTIAL_URL = re.compile(r"\b(?:postgres(?:ql)?|redis|mongodb|https?)://[^\s/:@'\"]+:[^\s@'\"]{6,}@([^\s/'\"]+)", re.IGNORECASE)

# Connection share links carry credentials; tests and docs must use
# example.com / documentation addresses in them.
SHARE_LINK = re.compile(r"\b(?:vless|vmess|trojan|ss|ssr|hysteria2|hy2|tuic|awg|wireguard|naive\+https)://[^\s'\"<>`]+", re.IGNORECASE)
EXAMPLE_HOST = re.compile(r"(?:example\.(?:com|net|org)|\.example\b|\.test\b|\.invalid\b|localhost|192\.0\.2\.|198\.51\.100\.|203\.0\.113\.|127\.0\.0\.1|\[?::1\]?|\b10\.|\b192\.168\.|\b172\.(?:1[6-9]|2[0-9]|3[01])\.)", re.IGNORECASE)

EMAIL = re.compile(r"\b[A-Za-z0-9._%+-]+@([A-Za-z0-9.-]+\.[A-Za-z]{2,})\b")
ALLOWED_EMAIL_DOMAINS = ("example.com", "example.net", "example.org", "users.noreply.github.com", "anthropic.com", "openwrt.org",
                         "github.com", "candidate",
                         # upstream package authors
                         "danrl.com", "amnezia.org", "mein.io", "zx2c4.com")
IPV4 = re.compile(r"(?<![0-9.])(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?![0-9.])")
HOME_PATH = re.compile(r"/(?:Users|home)/(?!runner(?:/|$)|build(?:/|$)|user(?:/|$)|example(?:/|$))[A-Za-z0-9._-]+/")

PRIVATE_NAMES = {".env", "custom-rules.json", "dnsfilter", "connections.json", "settings.json", "sysupgrade.conf"}
PRIVATE_SUFFIXES = {".key", ".pem", ".p12", ".pfx", ".ovpn", ".mobileconfig"}
# Router state files are fine as fixtures only under these test directories.
FIXTURE_DIRS = ("tests/", "runtime/", "server/engine-update/tests/", "server/awg-roam/tests/")


def tracked_files(root: Path, staged: bool) -> list[Path]:
    args = ["git", "-C", str(root), "diff", "--cached", "--name-only", "--diff-filter=ACMR", "-z"] if staged else \
        ["git", "-C", str(root), "ls-files", "--cached", "--others", "--exclude-standard", "-z"]
    try:
        out = subprocess.run(args, check=True, capture_output=True).stdout
    except (FileNotFoundError, subprocess.CalledProcessError):
        return [p for p in root.rglob("*") if p.is_file() and not any(x in SKIPPED_PARTS for x in p.relative_to(root).parts)]
    return [root / v.decode() for v in out.split(b"\0") if v and (root / v.decode()).is_file()]


def allowed_ip(value: str) -> bool:
    if value in NOT_ADDRESSES:
        return True
    try:
        a = ipaddress.ip_address(value)
    except ValueError:
        return True
    if value in ALLOWED_PUBLIC_IPS:
        return True
    if any(a in ipaddress.ip_network(n) for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "100.64.0.0/10", "0.0.0.0/8", "224.0.0.0/3", "192.88.99.0/24")):
        return True
    return a.is_private or a.is_loopback or a.is_unspecified or a.is_link_local or a.is_reserved or a.is_multicast


def check_policy(root: Path) -> list[str]:
    """The image policy stays the neutral public default."""
    findings = []
    pj = root / "policy" / "policy.json"
    if pj.is_file():
        try:
            status = json.loads(pj.read_text()).get("status")
        except (ValueError, AttributeError):
            status = None
        if status != "public-image-default":
            findings.append("policy/policy.json: status must stay public-image-default (private overlays live on the router)")
    for rs in sorted((root / "policy" / "rulesets").glob("*.json")):
        if rs.stem in {"local-domains", "local-ips"}:
            continue
        try:
            data = json.loads(rs.read_text())
        except ValueError:
            findings.append(f"policy/rulesets/{rs.name}: unreadable")
            continue
        entries = 0
        def count(v):
            nonlocal entries
            if isinstance(v, list):
                entries += sum(1 for x in v if isinstance(x, str))
                for x in v:
                    if not isinstance(x, str):
                        count(x)
            elif isinstance(v, dict):
                for k, x in v.items():
                    if k not in {"name", "class", "source", "description", "format", "version", "status", "note"}:
                        count(x)
        count(data)
        if entries:
            findings.append(f"policy/rulesets/{rs.name}: the public image ships empty lists; routing lists belong in the private overlay")
    return findings


def scan(root: Path, staged: bool = False) -> list[str]:
    findings: list[str] = []
    needles = blocked_needles(root)
    for path in tracked_files(root, staged):
        rel = path.relative_to(root).as_posix()
        if rel in ("ci/check_public_tree.py", ".private-needles"):
            continue
        name = path.name
        if path.suffix.lower() in PRIVATE_SUFFIXES or (name in PRIVATE_NAMES and not rel.startswith(FIXTURE_DIRS)):
            findings.append(f"{rel}: private file type")
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue
        low = text.lower()
        for n in needles:
            if n.lower() in low:
                findings.append(f"{rel}: live deployment identifier")
                break
        for label, pattern in SECRET_PATTERNS.items():
            if pattern.search(text):
                findings.append(f"{rel}: {label}")
        for m in SHARE_LINK.finditer(text):
            link = m.group(0)
            host = link.split("@", 1)[1] if "@" in link else link.split("://", 1)[1]
            if not EXAMPLE_HOST.search(host[:120]) and len(link) > 24:
                findings.append(f"{rel}: connection link to a non-example host")
                break
        if HOME_PATH.search(text):
            findings.append(f"{rel}: local home path")
        # Upstream copyright and maintainer lines are public attribution.
        attribution = re.compile(r"copyright|author|maintainer|signed-off|\(c\)", re.IGNORECASE)
        email_text = "\n".join(l for l in text.splitlines() if not attribution.search(l))
        for m in EMAIL.finditer(email_text):
            d = m.group(1).lower()
            if not d.endswith((".test", ".example", ".invalid")) and not any(d == a or d.endswith("." + a) for a in ALLOWED_EMAIL_DOMAINS):
                findings.append(f"{rel}: non-example email address")
                break
        for m in CREDENTIAL_URL.finditer(text):
            if not EXAMPLE_HOST.search(m.group(1)):
                findings.append(f"{rel}: credential URL")
                break
        # Tests may use any synthetic address; shipped code and docs may not.
        is_test = rel.startswith("tests/") or "/testdata/" in rel or "/tests/" in rel or rel.endswith("_test.go") or rel.endswith(".test.js")
        for v in ([] if is_test else IPV4.findall(text)):
            if not allowed_ip(v):
                findings.append(f"{rel}: public IPv4 address {v} (use 192.0.2.0/24, 198.51.100.0/24 or 203.0.113.0/24)")
                break
    if not staged:
        findings += check_policy(root)
    return sorted(set(findings))


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--root", type=Path, default=Path(__file__).resolve().parent.parent)
    ap.add_argument("--staged", action="store_true", help="scan only files staged for commit")
    a = ap.parse_args()
    found = scan(a.root.resolve(), a.staged)
    if found:
        print("FLR public tree check failed (private material must not be committed):")
        for f in found:
            print(f"- {f}")
        return 1
    print("FLR public tree check passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
