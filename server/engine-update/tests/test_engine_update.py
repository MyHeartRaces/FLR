"""Offline tests for flr-engine-update. Stdlib only; no network, no systemd."""
import hashlib
import importlib.machinery
import importlib.util
import io
import json
import os
import re
import shutil
import sys
import stat
import tempfile
import unittest
import urllib.request
from contextlib import redirect_stdout, redirect_stderr
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
SCRIPT = os.path.join(os.path.dirname(HERE), "flr-engine-update")
_loader = importlib.machinery.SourceFileLoader("flr_engine_update", SCRIPT)
eu = importlib.util.module_from_spec(importlib.util.spec_from_loader("flr_engine_update", _loader))
sys.modules["flr_engine_update"] = eu
_loader.exec_module(eu)

NOW = 1_800_000_000.0   # fixed fake clock
DAY = 86400


def elf(version, machine=62):
    head = b"\x7fELF" + bytes([2, 1, 1, 0]) + bytes(8) + bytes([2, 0]) + machine.to_bytes(2, "little")
    return head + b"\0" * 32 + ("VERSION=%s" % version).encode()


def sha(b):
    return hashlib.sha256(b).hexdigest()


class FakeHost(eu.Host):
    def __init__(self):
        self.t = NOW
        self.calls = []
        self.active = True
        self.ready = True
        self.not_ready_restarts = set()     # 1-based restart numbers whose ready line never appears
        self.failed_restarts = set()
        self.restart_rc = 0
        self.canary_result = (True, "ready")
        self.canary_queue = []
        self.canary_binaries = []
        self.receipts = []
        self.attempts = []
        self.canary_reads = 0
        self.canary_growth = (25000, 9 << 20)
        self.release = "6.12.1+deb13-amd64"

    def now(self):
        return self.t

    def sleep(self, s):
        self.t += s

    def uname_release(self):
        return self.release

    def systemctl(self, action, unit):
        self.calls.append((action, unit))
        if action == "restart" and len(self.calls) in self.failed_restarts:
            return 1, ""
        return self.restart_rc, ""

    def is_active(self, unit):
        return self.active

    def journal_has(self, unit, since, pattern):
        n = sum(1 for c in self.calls if c[0] == "restart")
        return self.ready and n not in self.not_ready_restarts

    def run_version(self, path):
        with open(path, "rb") as f:
            m = re.search(rb"VERSION=(\S+)", f.read())
        return "Version:\t%s\n" % m.group(1).decode() if m else "garbage"

    def listener_inode(self, pid, protocol, address, port):
        return (pid, protocol, address, port)

    def production_ownership(self, unit, sha, address, port, stats_port):
        return [500 + len(self.calls), "prod-udp", "prod-stats"]

    def loopback_stats(self, port, secret, path):
        return self.net.get_json("http://127.0.0.1:%d%s" % (port, path), {"Authorization": secret})

    def canary_counters(self, port, secret, user):
        self.canary_reads += 1
        return (0, 0) if self.canary_reads % 2 else self.canary_growth

    def qualify_router(self, argv, attempt):
        self.attempts.append(attempt)
        receipt = {"attempt": attempt, "outcome": "passed", "https_bytes": 8 << 20, "https_ms": 3000, "udp_answers": 3}
        if self.receipts:
            self.receipts.pop(0)(attempt, receipt)
        return receipt

    def canary(self, binary, config_path, timeout_s, pattern, probe=None):
        with open(config_path) as f:
            self.canary_binaries.append((binary, f.read()))
        ready, detail = self.canary_queue.pop(0) if self.canary_queue else self.canary_result
        return ready, probe(100 + len(self.canary_binaries)) if ready and probe else detail


class FakeNet:
    def __init__(self):
        self.releases = []
        self.files = {}       # url -> bytes
        self.online = {"router": 1}
        self.traffic = {"router": {"tx": 0, "rx": 0}}
        self.stats_fail = False
        self.seen_headers = []

    def get_json(self, url, headers=None):
        if url.startswith("http://127.0.0.1:25413"):
            self.seen_headers.append(headers)
            if self.stats_fail:
                raise OSError("down")
            return self.online if url.endswith("/online") else self.traffic
        return self.releases

    def get_text(self, url, headers=None):
        return self.files[url].decode()

    def download(self, url, dest, max_bytes=eu.MAX_DOWNLOAD):
        data = self.files[url]
        with open(dest, "wb") as f:
            f.write(data)
        return sha(data), len(data)


def make_release(net, ver, age_days=10, prerelease=False, draft=False, bad_hash=False,
                 digest=None, machine=62, content=None):
    data = content if content is not None else elf(ver, machine)
    bu, hu = "https://dl/%s/bin" % ver, "https://dl/%s/hashes" % ver
    net.files[bu] = data
    good = sha(data) if not bad_hash else "0" * 64
    net.files[hu] = ("%s  build/hysteria-linux-amd64\n%s  other\n" % (good, "1" * 64)).encode()
    asset = {"name": "hysteria-linux-amd64", "browser_download_url": bu}
    if digest:
        asset["digest"] = digest
    net.releases.append({
        "tag_name": "app/" + ver, "draft": draft, "prerelease": prerelease,
        "published_at": eu.iso(NOW - age_days * DAY),
        "assets": [asset, {"name": "hashes.txt", "browser_download_url": hu}]})
    return data


CONFIG_YAML = "listen: :443\nobfs:\n  type: gecko\ntrafficStats:\n  listen: 127.0.0.1:25413\n  secret: x\nmasquerade:\n  type: proxy\n"


class Base(unittest.TestCase):
    stats = True

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, True)
        p = lambda *a: os.path.join(self.tmp, *a)
        os.makedirs(p("bin"))
        os.makedirs(p("state"))
        self.binary = p("bin", "hysteria")
        self.old = elf("v2.14.0")
        with open(self.binary, "wb") as f:
            f.write(self.old)
        os.chmod(self.binary, 0o755)
        with open(p("server.yaml"), "w") as f:
            f.write(CONFIG_YAML)
        with open(p("secret"), "w") as f:
            f.write("TOPSECRET\n")
        cfg = eu.deep_merge(eu.DEFAULT_CONFIG, {
            "mode": "apply", "lock_path": p("state", "lock.json"), "work_dir": p("state", "work"),
            "gate": {"modules_root": p("modules"), "reboot_required_path": p("reboot-required")},
            "engines": {"hysteria": {
                "binary": self.binary, "config_path": p("server.yaml"),
                "stats_url": "http://127.0.0.1:25413" if self.stats else "",
                "stats_secret_file": p("secret") if self.stats else "",
                "router_user": "router" if self.stats else "",
                "qualification": {"command": ["/usr/local/libexec/qualify-router"], "router_build": "1" * 40,
                                  "profile_revision": "2" * 64, "relay_id": "relay-a", "address": "203.0.113.4",
                                  "bind_address": "192.0.2.4", "stats_port": 25414, "production_port": 443,
                                  "allow_restart": True}}}})
        self.cfg = cfg
        self.cfg_path = p("config.json")
        with open(self.cfg_path, "w") as f:
            json.dump(cfg, f)
        self.host, self.net = FakeHost(), FakeNet()
        self.host.net = self.net

    def updater(self):
        return eu.Updater(self.cfg, self.host, self.net)

    def lock(self):
        with open(self.cfg["lock_path"]) as f:
            return json.load(f)["engines"]["hysteria"]

    def binary_bytes(self):
        with open(self.binary, "rb") as f:
            return f.read()

    def grow_on_poll(self, tx=10**6, rx=10**6):
        """Router traffic appears only once the updater starts polling (sleep of 30 s)."""
        def sleep(s):
            self.host.t += s
            if s == eu.POLL_INTERVAL_S:
                self.net.traffic = {"router": {"tx": tx, "rx": rx}}
        self.host.sleep = sleep

    def cycle(self, apply=True):
        return self.updater().run_cycle(apply)


class TestPureHelpers(unittest.TestCase):
    def test_version_parse_and_compare(self):
        self.assertEqual(eu.parse_version("app/v2.14.0"), (2, 14, 0))
        self.assertGreater(eu.parse_version("v2.10.0"), eu.parse_version("v2.9.9"))
        self.assertIsNone(eu.parse_version("app/v2.14.0-rc1"))

    def test_version_in_output(self):
        self.assertTrue(eu.version_in_output("Version: v2.15.0\n", "v2.15.0"))
        self.assertFalse(eu.version_in_output("Version: v2.15.01", "v2.15.0"))
        self.assertFalse(eu.version_in_output("Version: v12.15.0", "v2.15.0"))

    def test_hashes_basename_match(self):
        txt = "%s  ./dist/hysteria-linux-amd64\n%s  hysteria-linux-amd64-avx\n" % ("a" * 64, "b" * 64)
        self.assertEqual(eu.parse_hashes(txt, "hysteria-linux-amd64"), "a" * 64)
        self.assertIsNone(eu.parse_hashes(txt, "nope"))

    def test_canary_config_replaces_listen_and_drops_stats(self):
        out = eu.make_canary_config(CONFIG_YAML, 40443)
        self.assertIn("listen: :40443\n", out)
        self.assertNotIn("trafficStats", out)
        self.assertNotIn("25413", out)
        self.assertIn("masquerade:", out)
        with self.assertRaises(eu.UpdaterError):
            eu.make_canary_config("obfs: x\n", 40443)
        with self.assertRaises(eu.UpdaterError):
            eu.make_canary_config("listen: :1\nlisten: :2\n", 40443)


class TestSelection(unittest.TestCase):
    def st(self, **kw):
        s = eu.new_engine_state()
        s["current"] = {"version": "v2.14.0", "sha256": "x", "installed_at": "t"}
        s.update(kw)
        return s

    def releases(self, specs):
        net = FakeNet()
        for v, age, pre in specs:
            make_release(net, v, age, prerelease=pre)
        net.releases.append({"tag_name": "app/v9.9.9", "draft": True, "prerelease": False,
                             "published_at": eu.iso(NOW - 99 * DAY), "assets": []})
        return eu.parse_releases(net.releases)

    def pick(self, rels, st, soak=3):
        r = eu.select_candidate(rels, st, soak, NOW)
        return eu.fmt_version(r.version) if r else None

    def test_newest_eligible_and_soak(self):
        rels = self.releases([("v2.15.0", 10, False), ("v2.16.0", 1, False)])
        self.assertEqual(self.pick(rels, self.st()), "v2.15.0")   # 2.16.0 still soaking
        self.assertEqual(self.pick(rels, self.st(), soak=0), "v2.16.0")

    def test_prerelease_draft_and_older_ignored(self):
        rels = self.releases([("v2.16.0", 10, True), ("v2.13.0", 10, False)])
        self.assertIsNone(self.pick(rels, self.st()))

    def test_blocked_skipped_newer_still_eligible(self):
        rels = self.releases([("v2.15.0", 10, False), ("v2.16.0", 10, False)])
        blocked = [{"version": "v2.16.0", "sha256": "", "reason": "r", "at": "t"}]
        self.assertEqual(self.pick(rels, self.st(blocked=blocked)), "v2.15.0")
        rels2 = self.releases([("v2.15.0", 10, False), ("v2.17.0", 10, False)])
        blocked2 = [{"version": "v2.15.0", "sha256": "", "reason": "r", "at": "t"}]
        self.assertEqual(self.pick(rels2, self.st(blocked=blocked2)), "v2.17.0")

    def test_hold_freezes(self):
        rels = self.releases([("v2.15.0", 10, False)])
        self.assertIsNone(self.pick(rels, self.st(hold=True)))


class TestVerification(Base):
    def test_checksum_mismatch_not_installed(self):
        make_release(self.net, "v2.15.0", bad_hash=True)
        with self.assertRaises(eu.UpdaterError) as c:
            self.cycle()
        self.assertEqual(c.exception.code, eu.EXIT_TRANSIENT)
        self.assertEqual(self.binary_bytes(), self.old)
        self.assertEqual(self.host.calls, [])

    def test_api_digest_mismatch(self):
        make_release(self.net, "v2.15.0", digest="sha256:" + "2" * 64)
        with self.assertRaisesRegex(eu.UpdaterError, "API digest"):
            self.cycle()

    def test_api_digest_match_ok(self):
        data = make_release(self.net, "v2.15.0")
        self.net.releases[0]["assets"][0]["digest"] = "sha256:" + sha(data)
        self.grow_on_poll()
        rep, code = self.cycle()
        self.assertEqual((rep["result"], code), ("promoted", 0))

    def test_elf_wrong_machine_and_not_elf(self):
        make_release(self.net, "v2.15.0", machine=183)
        with self.assertRaisesRegex(eu.UpdaterError, "e_machine"):
            self.cycle()
        self.net.releases.clear()
        make_release(self.net, "v2.15.0", content=b"#!/bin/sh\nVERSION=v2.15.0")
        with self.assertRaisesRegex(eu.UpdaterError, "not an ELF"):
            self.cycle()

    def test_version_output_must_match(self):
        make_release(self.net, "v2.15.0", content=elf("v2.99.0"))
        with self.assertRaisesRegex(eu.UpdaterError, "does not report"):
            self.cycle()

    def test_download_size_bound(self):
        class R(io.BytesIO):
            headers = {}
            def __enter__(self): return self
            def __exit__(self, *a): return False
        net = eu.Net(5, "ua")
        dest = os.path.join(self.tmp, "dl")
        with mock.patch.object(urllib.request, "urlopen", lambda req, timeout: R(b"x" * 100)):
            with self.assertRaisesRegex(eu.UpdaterError, "exceeds"):
                net.download("https://x/y", dest, max_bytes=50)
            self.assertEqual(net.download("https://x/y", dest, max_bytes=100)[1], 100)
        with self.assertRaises(eu.UpdaterError):
            net.get_text("file:///etc/passwd")
        # A GitHub release page larger than MAX_TEXT is valid JSON for get_json.
        big = json.dumps([{"tag_name": "v2.15.0", "body": "x" * (2 * 1024 * 1024)}]).encode()
        with mock.patch.object(urllib.request, "urlopen", lambda req, timeout: R(big)):
            self.assertEqual(net.get_json("https://api.github.com/x")[0]["tag_name"], "v2.15.0")
            with self.assertRaisesRegex(eu.UpdaterError, "too large"):
                net.get_text("https://x/hashes.txt")


class TestPromotion(Base):
    def test_apply_without_pairing_leaves_production_serving(self):
        self.cfg["engines"]["hysteria"]["qualification"] = None
        make_release(self.net, "v2.15.0")
        self.grow_on_poll()
        rep, code = self.cycle()
        self.assertEqual((rep["result"], code), ("deferred", 0))
        self.assertEqual(self.binary_bytes(), self.old)
        self.assertEqual(self.host.calls, [])

    def test_canary_failure_blocks(self):
        make_release(self.net, "v2.15.0")
        self.host.canary_queue = [(False, "exited early"), (True, "ready"), (False, "exited early")]
        rep, code = self.cycle()
        self.assertEqual((rep["result"], code), ("blocked", eu.EXIT_ROLLBACK))
        lk = self.lock()
        self.assertEqual(lk["blocked"][0]["version"], "v2.15.0")
        self.assertIn("canary failed", lk["blocked"][0]["reason"])
        self.assertEqual(self.binary_bytes(), self.old)
        self.assertEqual(self.host.calls, [])            # production never touched
        # blocked version is not retried
        self.assertEqual(self.cycle()[0]["result"], "up-to-date")

    def test_failed_router_trial_blocks_only_after_a_passing_control_and_repeat_failure(self):
        new = make_release(self.net, "v2.15.0")
        self.host.receipts = [lambda _, r: r.update(outcome="failed"), lambda *_: None,
                              lambda _, r: r.update(outcome="failed")]
        rep, code = self.cycle()
        self.assertEqual((rep["result"], code), ("blocked", eu.EXIT_ROLLBACK))
        self.assertEqual([a["candidate_sha256"] for a in self.host.attempts], [sha(new), sha(self.old), sha(new)])
        self.assertEqual(len({a["nonce"] for a in self.host.attempts}), 3)
        self.assertEqual(self.binary_bytes(), self.old)
        self.assertEqual(self.host.calls, [])

    def test_wrong_or_stale_router_receipt_leaves_production_serving(self):
        make_release(self.net, "v2.15.0")
        stale = lambda _, r: r.update(attempt={**r["attempt"], "nonce": "previous-attempt"})
        wrong_listener = lambda _, r: r.update(attempt={**r["attempt"], "port": 443})
        short_transfer = lambda _, r: r.update(https_bytes=(8 << 20) - 1)
        expired = lambda *_: self.host.sleep(120)
        for edit in (stale, wrong_listener, short_transfer, expired):
            with self.subTest(edit=edit):
                self.host.receipts = [edit]
                rep, code = self.cycle()
                self.assertEqual((rep["result"], code), ("inconclusive", eu.EXIT_TRANSIENT))
                self.assertEqual(self.lock()["blocked"], [])
                self.assertEqual(self.binary_bytes(), self.old)
                self.assertEqual(self.host.calls, [])

    def test_valid_router_receipt_requires_candidate_listener_growth(self):
        make_release(self.net, "v2.15.0")
        self.host.canary_growth = (0, 9 << 20)
        rep, code = self.cycle()
        self.assertEqual((rep["result"], code), ("inconclusive", eu.EXIT_TRANSIENT))
        self.assertEqual(self.binary_bytes(), self.old)
        self.assertEqual(self.host.calls, [])

    def test_final_endpoint_requires_a_fresh_successful_probe(self):
        new = make_release(self.net, "v2.15.0")
        self.grow_on_poll()
        self.host.receipts = [lambda *_: None, lambda _, r: r.update(outcome="inconclusive")]
        rep, code = self.cycle()
        self.assertEqual((rep["result"], code), ("inconclusive", eu.EXIT_TRANSIENT))
        self.assertEqual(self.binary_bytes(), self.old)
        self.assertEqual(self.lock()["blocked"], [])
        self.assertEqual([(a["listener"], a["port"], a["candidate_sha256"]) for a in self.host.attempts],
                         [("candidate", 40443, sha(new)), ("production", 443, sha(new))])
        self.assertNotEqual(self.host.attempts[0]["nonce"], self.host.attempts[1]["nonce"])
        self.assertEqual(self.host.calls, [("restart", "flint-hysteria")] * 2)

    def test_router_activity_during_canary_defers_restart(self):
        make_release(self.net, "v2.15.0")

        def subscriber_resumed(*_):
            self.net.traffic = {"router": {"tx": 10**7, "rx": 10**7}}

        self.host.receipts = [subscriber_resumed]
        rep, code = self.cycle()
        self.assertEqual((rep["result"], code), ("deferred", 0))
        self.assertEqual(self.lock()["candidate"]["idle_check"]["decision"], "busy")
        self.assertEqual(self.binary_bytes(), self.old)
        self.assertEqual(self.host.calls, [])

    def test_receipt_expiring_in_copy_restores_on_disk_without_restart(self):
        make_release(self.net, "v2.15.0")
        self.grow_on_poll()
        copy = eu.copy_atomic

        def slow_promotion(src, dst):
            copy(src, dst)
            if dst == self.binary and "staged" in src:
                self.host.sleep(120)

        with mock.patch.object(eu, "copy_atomic", slow_promotion):
            rep, code = self.cycle()
        self.assertEqual((rep["result"], code), ("inconclusive", eu.EXIT_TRANSIENT))
        self.assertEqual(self.lock()["candidate"]["stage"], "ready")
        self.assertEqual(self.binary_bytes(), self.old)
        self.assertEqual(self.host.calls, [])

    def test_interrupted_install_reconciles_still_serving_old_process_without_restart(self):
        for after_replace in (False, True):
            with self.subTest(after_replace=after_replace):
                new = make_release(self.net, "v2.15.0")
                copy = eu.copy_atomic

                def interrupt_promotion(src, dst):
                    if dst == self.binary and "staged" in src:
                        if after_replace:
                            copy(src, dst)
                        raise InterruptedError("test interruption")
                    copy(src, dst)

                with mock.patch.object(eu, "copy_atomic", interrupt_promotion):
                    with self.assertRaises(InterruptedError):
                        self.cycle()
                self.assertEqual(self.lock()["candidate"]["stage"], "installing")
                self.assertEqual(self.binary_bytes(), new if after_replace else self.old)
                self.net.releases.clear()
                rep, code = self.cycle()
                self.assertEqual((rep["result"], code), ("up-to-date", 0))
                self.assertIsNone(self.lock()["candidate"])
                self.assertEqual(self.binary_bytes(), self.old)
                self.assertEqual(self.host.calls, [])

    def test_production_config_change_invalidates_receipt(self):
        make_release(self.net, "v2.15.0")

        def change_config(*_):
            with open(self.cfg["engines"]["hysteria"]["config_path"], "a") as f:
                f.write("# changed while qualifying\n")

        self.host.receipts = [change_config]
        rep, code = self.cycle()
        self.assertEqual((rep["result"], code), ("inconclusive", eu.EXIT_TRANSIENT))
        self.assertEqual(self.binary_bytes(), self.old)
        self.assertEqual(self.host.calls, [])

    def test_canary_uses_temp_config_with_port(self):
        make_release(self.net, "v2.15.0")
        self.cycle()
        _bin, text = self.host.canary_binaries[0]
        self.assertIn("listen: 192.0.2.4:40443", text)
        self.assertIn("listen: 127.0.0.1:25414", text)
        self.assertNotIn("127.0.0.1:25413", text)
        self.assertIn("obfs:\n  type: gecko", text)
        self.assertFalse(any(n.startswith("canary-") for n in os.listdir(self.cfg["work_dir"])))
        with open(self.cfg["engines"]["hysteria"]["config_path"]) as f:
            self.assertEqual(f.read(), CONFIG_YAML)     # production config untouched

    def grow_by_sleep(self, window_bytes, poll_bytes=10**6):
        def sleep(s):
            self.host.t += s
            if s == self.cfg["engines"]["hysteria"]["idle_window_s"]:
                t = self.net.traffic["router"]
                self.net.traffic = {"router": {"tx": t["tx"] + window_bytes, "rx": t["rx"]}}
            elif s == eu.POLL_INTERVAL_S:
                self.net.traffic = {"router": {"tx": poll_bytes, "rx": poll_bytes}}
        self.host.sleep = sleep

    def test_deferred_when_router_busy_then_promoted(self):
        new = make_release(self.net, "v2.15.0")
        self.net.online = {"router": 1}
        self.grow_by_sleep(5 * 10**6)                     # real failover traffic
        rep, code = self.cycle()
        self.assertEqual((rep["result"], code), ("deferred", 0))
        cand = self.lock()["candidate"]
        self.assertEqual(cand["stage"], "ready")
        self.assertEqual(cand["idle_check"]["decision"], "busy")
        self.assertEqual(cand["idle_check"]["measured_bytes"], 5 * 10**6)
        self.assertEqual(self.binary_bytes(), self.old)
        self.assertEqual(self.host.calls, [])
        st = json.loads(self.run_status())["engines"]["hysteria"]["candidate"]
        self.assertEqual(st["idle_check"]["decision"], "busy")
        self.net.online = {"router": 1}
        self.net.traffic = {"router": {"tx": 0, "rx": 0}}
        self.grow_on_poll()                               # probe-level in the idle window now
        rep, code = self.cycle()
        self.assertEqual(rep["result"], "promoted")
        self.assertEqual(self.binary_bytes(), new)

    def run_status(self):
        out = io.StringIO()
        with redirect_stdout(out):
            eu.main(["--config", self.cfg_path, "status"], self.host, self.net)
        return out.getvalue()

    def test_online_but_probe_level_traffic_counts_as_idle(self):
        new = make_release(self.net, "v2.15.0")
        self.net.online = {"router": 1}
        self.grow_by_sleep(2000)
        rep, code = self.cycle()
        self.assertEqual((rep["result"], code), ("promoted", 0))
        self.assertEqual(rep["idle_check"]["decision"], "idle")
        self.assertEqual(rep["idle_check"]["measured_bytes"], 2000)
        self.assertEqual(self.binary_bytes(), new)

    def test_stats_unreachable_with_idle_defers_and_any_rolls_back(self):
        make_release(self.net, "v2.15.0")
        self.net.stats_fail = True
        rep, code = self.cycle()
        self.assertEqual((rep["result"], code), ("deferred", 0))
        self.assertEqual(self.binary_bytes(), self.old)
        self.cfg["engines"]["hysteria"]["promote_when"] = "any"
        rep, code = self.cycle()
        self.assertEqual(rep["result"], "inconclusive")
        self.assertEqual(self.binary_bytes(), self.old)

    def test_promote_when_any_ignores_online(self):
        self.cfg["engines"]["hysteria"]["promote_when"] = "any"
        make_release(self.net, "v2.15.0")
        self.net.online = {"router": 3}
        self.grow_on_poll()
        self.assertEqual(self.cycle()[0]["result"], "promoted")

    def test_service_only_promotion_without_stats_is_deferred(self):
        Base.stats = False
        self.addCleanup(setattr, Base, "stats", True)
        self.setUp()
        self.cfg["engines"]["hysteria"]["promote_when"] = "any"
        make_release(self.net, "v2.15.0")
        rep, code = self.cycle()
        self.assertEqual((rep["result"], code), ("deferred", 0))
        lk = self.lock()
        self.assertEqual(lk["current"]["version"], "v2.14.0")
        self.assertEqual(lk["evidence"], "service-only")
        self.assertIsNone(lk["candidate"])
        self.assertEqual(self.binary_bytes(), self.old)
        self.assertEqual(self.host.calls, [])

    def test_post_promotion_success_inline(self):
        new = make_release(self.net, "v2.15.0")
        self.grow_on_poll(70000, 80000)
        rep, code = self.cycle()
        self.assertEqual((rep["result"], code), ("promoted", 0))
        lk = self.lock()
        self.assertEqual(lk["current"]["version"], "v2.15.0")
        self.assertEqual(lk["last_good"]["version"], "v2.15.0")
        self.assertEqual(lk["evidence"], "router-traffic")
        self.assertIsNone(lk["candidate"])
        self.assertEqual(self.binary_bytes(), new)
        self.assertTrue(os.path.isfile(self.binary + ".last-good-v2.15.0"))
        self.assertFalse(os.path.exists(self.binary + ".last-good-v2.14.0"))   # pruned
        self.assertTrue(self.binary_bytes() and os.stat(self.binary).st_mode & stat.S_IXUSR)
        self.assertTrue(all("TOPSECRET" not in str(h) or h == {"Authorization": "TOPSECRET"}
                            for h in self.net.seen_headers))

    def test_verification_without_wan_control_rolls_back_without_blocking(self):
        make_release(self.net, "v2.15.0")
        self.net.traffic = {"router": {"tx": 100, "rx": 100}}    # never grows
        rep, code = self.cycle()
        self.assertEqual((rep["result"], code), ("inconclusive", eu.EXIT_TRANSIENT))
        lk = self.lock()
        self.assertEqual(lk["current"]["version"], "v2.14.0")
        self.assertEqual(lk["blocked"], [])
        self.assertIsNone(lk["candidate"])
        self.assertEqual(self.binary_bytes(), self.old)
        self.assertEqual(self.host.calls.count(("restart", "flint-hysteria")), 2)
        self.assertGreaterEqual(self.host.t - NOW, 20 * 60)

    def test_deferred_verification_across_runs(self):
        self.cfg["engines"]["hysteria"]["verify_inline"] = False
        make_release(self.net, "v2.15.0")
        rep, _ = self.cycle()
        self.assertEqual(rep["result"], "verifying")
        self.assertEqual(self.lock()["candidate"]["stage"], "verifying")
        self.host.t += 600
        self.assertEqual(self.cycle()[0]["result"], "verifying")
        self.host.t += 30         # follow-up while the verification window is open
        self.net.traffic = {"router": {"tx": 10**6, "rx": 10**6}}
        rep, code = self.cycle()
        self.assertEqual((rep["verification"], code), ("verified", 0))
        self.assertEqual(self.lock()["evidence"], "router-traffic")

    def test_decreasing_counters_do_not_supply_warm_verification_growth(self):
        self.cfg["engines"]["hysteria"]["verify_inline"] = False
        self.net.traffic = {"router": {"tx": 1_000_000, "rx": 1_000_000}}
        make_release(self.net, "v2.15.0")
        self.assertEqual(self.cycle()[0]["result"], "verifying")
        self.net.traffic = {"router": {"tx": 999_000, "rx": 999_000}}
        self.assertEqual(self.cycle()[0]["result"], "verifying")
        self.net.traffic = {"router": {"tx": 1_008_000, "rx": 1_008_000}}
        self.assertEqual(self.cycle()[0]["verification"], "verified")

    def test_warm_stats_cannot_qualify_a_binary_replaced_on_disk(self):
        self.cfg["engines"]["hysteria"]["verify_inline"] = False
        make_release(self.net, "v2.15.0")
        self.assertEqual(self.cycle()[0]["result"], "verifying")
        get_json = self.net.get_json

        def replace_disk_binary(url, headers=None):
            if url.endswith("/traffic"):
                with open(self.binary, "wb") as f:
                    f.write(elf("v2.16.0"))
            return get_json(url, headers)

        self.net.traffic = {"router": {"tx": 1_000_000, "rx": 1_000_000}}
        self.net.get_json = replace_disk_binary
        rep, code = self.cycle()
        self.assertEqual((rep["result"], code), ("inconclusive", eu.EXIT_TRANSIENT))
        self.assertEqual(self.binary_bytes(), self.old)
        self.assertEqual(self.lock()["last_good"]["sha256"], sha(self.old))
        self.assertFalse(os.path.exists(self.binary + ".last-good-v2.15.0"))

    def test_deferred_verification_expiry_rolls_back(self):
        self.cfg["engines"]["hysteria"]["verify_inline"] = False
        make_release(self.net, "v2.15.0")
        self.cycle()
        self.host.t += 7200
        self.net.traffic = {"router": {"tx": 1000000, "rx": 1000000}}
        rep, code = self.cycle()
        self.assertEqual((rep["result"], code), ("inconclusive", eu.EXIT_TRANSIENT))
        self.assertEqual(self.lock()["current"]["version"], "v2.14.0")

    def test_invalid_previous_binary_backup_prevents_restart(self):
        self.cycle()
        backup = self.binary + ".last-good-v2.14.0"
        os.unlink(backup)
        make_release(self.net, "v2.15.0")
        copy_atomic = eu.copy_atomic

        def copy_changed(source, destination):
            copy_atomic(source, destination)
            if destination == backup:
                with open(destination, "wb") as f:
                    f.write(elf("v2.16.0"))

        with mock.patch.object(eu, "copy_atomic", side_effect=copy_changed):
            with self.assertRaisesRegex(eu.UpdaterError, "previous binary backup checksum mismatch"):
                self.cycle()
        self.assertEqual(self.binary_bytes(), self.old)
        self.assertEqual(self.host.calls, [])

    def test_service_failure_rolls_back_and_blocks(self):
        make_release(self.net, "v2.15.0")
        self.host.not_ready_restarts = {1}                 # candidate fails, restored last-good is fine
        rep, code = self.cycle()
        self.assertEqual((rep["result"], code), ("rolled-back", eu.EXIT_ROLLBACK))
        lk = self.lock()
        self.assertEqual(lk["current"]["version"], "v2.14.0")
        self.assertIn("service failure", lk["blocked"][0]["reason"])
        self.assertEqual(self.binary_bytes(), self.old)

    def test_restart_failure_rolls_back(self):
        make_release(self.net, "v2.15.0")
        self.host.failed_restarts = {1}
        rep, code = self.cycle()
        self.assertEqual(rep["result"], "rolled-back")
        self.assertEqual(self.binary_bytes(), self.old)

    def test_check_mode_changes_nothing(self):
        make_release(self.net, "v2.15.0")
        rep, code = self.cycle(apply=False)
        self.assertEqual((rep["result"], rep["available"], code), ("update-available", "v2.15.0", 0))
        self.assertEqual(self.binary_bytes(), self.old)
        self.assertEqual(self.host.calls, [])

    def test_hold_blocks_updates(self):
        make_release(self.net, "v2.15.0")
        u = self.updater()
        u.st["hold"] = True
        u.save()
        self.assertEqual(self.cycle()[0]["result"], "held")


class TestLockFile(Base):
    def test_format_permissions_and_atomicity(self):
        self.cycle()
        with open(self.cfg["lock_path"]) as f:
            data = json.load(f)
        self.assertEqual(data["format"], "flr-compat-lock-v1")
        st = data["engines"]["hysteria"]
        self.assertEqual(set(st), {"current", "last_good", "candidate", "blocked", "hold", "evidence", "last_attempt"})
        self.assertEqual(set(st["current"]), {"version", "sha256", "installed_at"})
        self.assertEqual(st["current"]["version"], "v2.14.0")
        self.assertEqual(stat.S_IMODE(os.stat(self.cfg["lock_path"]).st_mode), 0o600)
        self.assertEqual([n for n in os.listdir(os.path.dirname(self.cfg["lock_path"])) if n.startswith(".tmp")], [])

    def test_failed_write_leaves_old_lock_intact(self):
        u = self.updater()
        u.save()
        with open(self.cfg["lock_path"]) as f:
            before = f.read()
        with mock.patch.object(eu.os, "replace", side_effect=OSError("boom")):
            with self.assertRaises(OSError):
                u.store.save({"format": eu.LOCK_FORMAT, "engines": {"x": 1}})
        with open(self.cfg["lock_path"]) as f:
            self.assertEqual(f.read(), before)
        self.assertEqual([n for n in os.listdir(os.path.dirname(self.cfg["lock_path"])) if n.startswith(".tmp")], [])

    def test_bad_format_rejected(self):
        with open(self.cfg["lock_path"], "w") as f:
            json.dump({"format": "other"}, f)
        with self.assertRaises(eu.UpdaterError):
            self.updater()

    def test_flock_busy(self):
        store = eu.LockStore(self.cfg["lock_path"])
        with store.exclusive():
            with self.assertRaises(eu.UpdaterError) as c:
                with eu.LockStore(self.cfg["lock_path"]).exclusive():
                    pass
            self.assertEqual(c.exception.code, eu.EXIT_BUSY)


class TestKernelGate(Base):
    def kernel(self, name, module=None, with_kernel_dir=True):
        d = os.path.join(self.tmp, "modules", name)
        os.makedirs(os.path.join(d, "kernel") if with_kernel_dir else d)
        if module:
            os.makedirs(os.path.join(d, os.path.dirname(module)), exist_ok=True)
            open(os.path.join(d, module), "w").close()

    def test_newest_without_module_is_unsafe(self):
        self.kernel("6.12.48+deb13-amd64", "updates/dkms/amneziawg.ko.xz")
        self.kernel("6.12.57+deb13-cloud-amd64")
        self.kernel("6.1.0-leftover", "updates/dkms/amneziawg.ko", with_kernel_dir=False)  # not a real kernel
        open(os.path.join(self.tmp, "reboot-required"), "w").close()
        rep = eu.kernel_gate(self.cfg["gate"], "6.12.48+deb13-amd64")
        self.assertEqual([k["version"] for k in rep["kernels"]], ["6.12.48+deb13-amd64", "6.12.57+deb13-cloud-amd64"])
        self.assertEqual([k["amneziawg"] for k in rep["kernels"]], [True, False])
        self.assertTrue(rep["reboot_required"])
        self.assertFalse(rep["safe_to_reboot"])
        self.assertIn("NOT EXECUTED", rep["suggestion"])
        out = io.StringIO()
        with redirect_stdout(out):
            self.assertEqual(eu.main(["--config", self.cfg_path, "gate"], self.host, self.net), eu.EXIT_UNSAFE)

    def test_safe_when_newest_has_module(self):
        self.kernel("6.12.57+deb13-cloud-amd64", "extra/amneziawg.ko.zst")
        rep = eu.kernel_gate(self.cfg["gate"])
        self.assertTrue(rep["safe_to_reboot"])
        self.assertFalse(rep["reboot_required"])
        with redirect_stdout(io.StringIO()):
            self.assertEqual(eu.main(["--config", self.cfg_path, "gate"], self.host, self.net), 0)

    def test_hidden_module_tree_is_unknown_not_unsafe(self):
        # A sandbox that hides /lib/modules (ProtectKernelModules) shows no
        # kernels at all; that is "cannot judge", not "newest lacks AWG".
        rep = eu.kernel_gate(self.cfg["gate"])
        self.assertIsNone(rep["safe_to_reboot"])
        self.assertIn("no kernels visible", rep["error"])
        self.assertNotIn("suggestion", rep)
        with redirect_stdout(io.StringIO()):
            self.assertEqual(eu.main(["--config", self.cfg_path, "gate"], self.host, self.net), eu.EXIT_UNSAFE)

    def test_service_unit_keeps_module_tree_visible(self):
        with open(os.path.join(os.path.dirname(HERE), "flr-engine-update.service")) as f:
            unit = f.read()
        self.assertNotIn("ProtectKernelModules=true", unit)
        self.assertIn("CapabilityBoundingSet=~CAP_SYS_MODULE", unit)

    def test_numeric_ordering(self):
        self.kernel("6.9.0-1-amd64", "updates/dkms/amneziawg.ko")
        self.kernel("6.12.0-1-amd64")
        self.assertEqual(eu.kernel_gate(self.cfg["gate"])["newest"], "6.12.0-1-amd64")


class TestCLI(Base):
    def run_cli(self, *args):
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            code = eu.main(["--config", self.cfg_path, *args], self.host, self.net)
        return code, out.getvalue(), err.getvalue()

    def test_status_shape(self):
        self.assertIsNone(json.loads(self.run_cli("status")[1])["engines"]["hysteria"]["current"])  # fresh lock
        self.cycle()                                      # bootstraps current from the binary
        code, out, _ = self.run_cli("status")
        data = json.loads(out)
        self.assertEqual(code, 0)
        self.assertEqual(data["format"], "flr-compat-lock-v1")
        self.assertEqual(data["engines"]["hysteria"]["current"]["version"], "v2.14.0")
        self.assertTrue(data["engines"]["hysteria"]["stats_configured"])
        self.assertIn("safe_to_reboot", data["kernel_gate"])
        self.assertNotIn("TOPSECRET", out)

    def test_check_output_shape_and_no_changes(self):
        make_release(self.net, "v2.15.0")
        code, out, _ = self.run_cli("check")
        data = json.loads(out)
        self.assertEqual((code, data["result"], data["available"], data["mode"]), (0, "update-available", "v2.15.0", "check"))
        self.assertIn("kernel_gate", data)
        self.assertEqual(self.binary_bytes(), self.old)

    def test_run_honors_config_mode_check(self):
        self.cfg["mode"] = "check"
        with open(self.cfg_path, "w") as f:
            json.dump(self.cfg, f)
        make_release(self.net, "v2.15.0")
        code, out, _ = self.run_cli("run")
        self.assertEqual(json.loads(out)["result"], "update-available")
        self.assertEqual(self.binary_bytes(), self.old)
        self.assertFalse(os.path.exists(self.cfg["lock_path"]))

    def test_hold_unhold_unblock_rollback(self):
        self.assertEqual(self.run_cli("hold", "hysteria")[0], 0)
        self.assertTrue(self.updater().st["hold"])
        self.assertEqual(self.run_cli("unhold", "hysteria")[0], 0)
        self.assertFalse(self.updater().st["hold"])
        self.assertEqual(self.run_cli("hold", "nginx")[0], eu.EXIT_ERROR)
        u = self.updater()
        u.st["blocked"].append({"version": "v2.15.0", "sha256": "", "reason": "r", "at": "t"})
        u.save()
        self.assertEqual(self.run_cli("unblock", "hysteria", "v2.15.0")[0], 0)
        self.assertEqual(self.updater().st["blocked"], [])
        self.assertEqual(self.run_cli("unblock", "hysteria", "v2.15.0")[0], eu.EXIT_ERROR)
        self.assertEqual(self.run_cli("rollback", "hysteria")[0], eu.EXIT_ERROR)   # nothing to roll back to

    def test_manual_rollback(self):
        make_release(self.net, "v2.15.0")
        self.cfg["engines"]["hysteria"]["verify_inline"] = False
        self.cycle()                                    # now verifying, last_good = v2.14.0
        code, out, _ = self.run_cli("rollback", "hysteria")
        self.assertEqual(code, 0)
        lk = self.lock()
        self.assertEqual(lk["current"]["version"], "v2.14.0")
        self.assertEqual(lk["blocked"][0]["reason"], "manual rollback")
        self.assertEqual(self.binary_bytes(), self.old)

    def test_missing_config_exit_code(self):
        out = io.StringIO()
        with redirect_stderr(out):
            self.assertEqual(eu.main(["--config", os.path.join(self.tmp, "nope.json"), "status"]), eu.EXIT_ERROR)


class TestReviewFixes(Base):
    def test_check_is_side_effect_free_during_interrupted_install(self):
        make_release(self.net, "v2.15.0")
        self.cycle(apply=False)
        u = self.updater()
        u._bootstrap_current()
        u.st["last_good"] = dict(u.st["current"])
        u.st["candidate"] = {"version": "v2.15.0", "sha256": "x", "stage": "installing",
                             "started_at": eu.iso(NOW), "baseline": None}
        u.save()
        with open(self.cfg["lock_path"], "rb") as f:
            before = f.read()
        mtime = os.stat(self.cfg["lock_path"]).st_mtime_ns
        bin_before = self.binary_bytes()
        out = io.StringIO()
        with redirect_stdout(out), redirect_stderr(io.StringIO()):
            code = eu.main(["--config", self.cfg_path, "check"], self.host, self.net)
        data = json.loads(out.getvalue())
        self.assertEqual((code, data["result"]), (0, "would-recover-interrupted-promotion"))
        self.assertEqual(self.host.calls, [])
        self.assertEqual(self.binary_bytes(), bin_before)
        self.assertEqual(os.stat(self.cfg["lock_path"]).st_mtime_ns, mtime)
        with open(self.cfg["lock_path"], "rb") as f:
            self.assertEqual(f.read(), before)

    def test_check_takes_the_run_lock(self):
        with eu.LockStore(self.cfg["lock_path"]).exclusive():
            with redirect_stderr(io.StringIO()):
                self.assertEqual(eu.main(["--config", self.cfg_path, "check"], self.host, self.net), eu.EXIT_BUSY)

    def test_check_with_verifying_candidate_does_not_poll(self):
        self.cfg["engines"]["hysteria"]["verify_inline"] = False
        make_release(self.net, "v2.15.0")
        self.cycle()
        before = self.host.t
        out = io.StringIO()
        with redirect_stdout(out):
            eu.main(["--config", self.cfg_path, "check"], self.host, self.net)
        self.assertEqual(json.loads(out.getvalue())["result"], "verifying")
        self.assertEqual(self.host.t, before)

    def test_offline_router_defers(self):
        make_release(self.net, "v2.15.0")
        self.net.online = {"router": 0}
        rep, code = self.cycle()
        self.assertEqual((rep["result"], code), ("deferred", 0))
        self.assertEqual(self.lock()["candidate"]["idle_check"]["decision"], "offline")
        self.assertEqual(self.binary_bytes(), self.old)
        self.assertEqual(self.host.calls, [])

    def test_any_promotes_even_when_offline(self):
        self.cfg["engines"]["hysteria"]["promote_when"] = "any"
        make_release(self.net, "v2.15.0")
        self.net.online = {"router": 0}
        rep, _ = self.cycle()
        self.assertEqual(rep["promoted"], "v2.15.0")

    def test_no_stats_with_idle_defers_and_status_says_why(self):
        Base.stats = False
        self.addCleanup(setattr, Base, "stats", True)
        self.setUp()
        make_release(self.net, "v2.15.0")
        rep, code = self.cycle()
        self.assertEqual((rep["result"], code), ("deferred", 0))
        self.assertIn("stats API", rep["reason"])
        self.assertEqual(self.binary_bytes(), self.old)
        self.assertIn("promotion_note", json.loads(self.run_status())["engines"]["hysteria"])

    def run_status(self):
        out = io.StringIO()
        with redirect_stdout(out):
            eu.main(["--config", self.cfg_path, "status"], self.host, self.net)
        return out.getvalue()

    def test_low_traffic_passes_default_threshold(self):
        self.assertEqual(self.cfg["engines"]["hysteria"]["verify_min_bytes"], 4096)
        make_release(self.net, "v2.15.0")
        self.grow_on_poll(5000, 6000)
        rep, code = self.cycle()
        self.assertEqual((rep["result"], code), ("promoted", 0))
        self.assertEqual(self.lock()["evidence"], "router-traffic")

    def test_three_consecutive_polls_with_small_growth_pass(self):
        make_release(self.net, "v2.15.0")
        n = {"v": 0}

        def sleep(s):
            self.host.t += s
            if s == eu.POLL_INTERVAL_S:
                n["v"] += 100                      # 100 B/poll each way: far below 4096 in total
                self.net.traffic = {"router": {"tx": n["v"], "rx": n["v"]}}
        self.host.sleep = sleep
        rep, code = self.cycle()
        self.assertEqual((rep["result"], code), ("promoted", 0))
        self.assertGreaterEqual(rep["router_growth"]["consecutive_polls"], 3)
        self.assertLess(rep["router_growth"]["tx"], 4096)

    def test_never_connected_is_inconclusive_not_blocked(self):
        make_release(self.net, "v2.15.0")
        self.cfg["engines"]["hysteria"]["promote_when"] = "any"
        self.net.online = {"router": 0}
        self.net.traffic = {"router": {"tx": 0, "rx": 0}}
        rep, code = self.cycle()
        self.assertEqual((rep["result"], code), ("inconclusive", eu.EXIT_TRANSIENT))
        lk = self.lock()
        self.assertEqual(lk["blocked"], [])
        self.assertEqual(lk["current"]["version"], "v2.14.0")
        self.assertEqual(lk["last_attempt"]["reason"], "inconclusive: router not connected")
        self.assertEqual(self.binary_bytes(), self.old)
        self.assertEqual(self.host.calls.count(("restart", "flint-hysteria")), 2)
        # eligible again on the next run
        self.assertEqual(self.cycle(apply=False)[0]["available"], "v2.15.0")

    def test_control_canary_failure_is_inconclusive(self):
        make_release(self.net, "v2.15.0")
        self.host.canary_queue = [(False, "port in use"), (False, "port in use")]
        rep, code = self.cycle()
        self.assertEqual((rep["result"], code), ("inconclusive", eu.EXIT_TRANSIENT))
        lk = self.lock()
        self.assertEqual(lk["blocked"], [])
        self.assertEqual(lk["last_attempt"]["result"], "inconclusive")
        self.assertEqual(len(self.host.canary_binaries), 2)
        self.assertEqual(self.host.canary_binaries[1][0], self.binary)   # control used the current binary
        self.assertEqual(self.host.calls, [])

    def test_rollback_with_failing_last_good_does_not_block(self):
        make_release(self.net, "v2.15.0")
        self.host.not_ready_restarts = {1, 2}             # candidate AND restored last-good fail
        rep, code = self.cycle()
        self.assertEqual((rep["result"], code), ("environment-failure", eu.EXIT_ROLLBACK))
        lk = self.lock()
        self.assertEqual(lk["blocked"], [])
        self.assertEqual(lk["last_attempt"]["result"], "environment-failure")
        self.assertEqual(self.binary_bytes(), self.old)

    def test_failed_rollback_restart_retains_recovery_marker(self):
        make_release(self.net, "v2.15.0")
        self.host.failed_restarts = {1, 2}
        rep, code = self.cycle()
        self.assertEqual((rep["result"], code), ("environment-failure", eu.EXIT_ROLLBACK))
        self.assertEqual(self.lock()["candidate"]["stage"], "installing")
        self.assertEqual(self.lock()["blocked"], [])
        self.assertEqual(self.binary_bytes(), self.old)
        self.net.releases.clear()
        rep, code = self.cycle()
        self.assertEqual((rep["result"], code), ("up-to-date", 0))
        self.assertIsNone(self.lock()["candidate"])
        self.assertEqual(self.host.calls, [("restart", "flint-hysteria")] * 3)

    def test_service_unit_allows_netlink(self):
        with open(os.path.join(os.path.dirname(HERE), "flr-engine-update.service")) as f:
            self.assertIn("AF_NETLINK", f.read())


class TestExampleConfig(unittest.TestCase):
    def test_example_config_valid(self):
        eu.load_config(os.path.join(os.path.dirname(HERE), "config.example.json"))


if __name__ == "__main__":
    unittest.main()
