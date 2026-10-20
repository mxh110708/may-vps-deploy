"""Template and portable-profile regressions; no personal configurations or network."""
import copy
import json
from pathlib import Path
import sys
import unittest

from ruamel.yaml import YAML

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from client_compatibility import MAX_PROFILE_BYTES, PUBLIC_RULE_NAMES, public_rule_url, serialize_profile
from build_client_authority import validate_rendered_references


class ClientCompatibilityTests(unittest.TestCase):
    def setUp(self):
        self.clash = YAML(typ="safe").load((ROOT / "templates/client/clash-general.template.yaml").read_text(encoding="utf-8"))
        self.sing = json.loads((ROOT / "templates/client/sing-box-general.template.json").read_text(encoding="utf-8"))

    def test_public_templates_and_references(self):
        validate_rendered_references(self.clash, self.sing)
        self.assertEqual(self.clash["tun"]["dns-hijack"], ["any:53", "tcp://any:53"])
        self.assertFalse(self.clash["tun"]["enable"])
        mixed = [item for item in self.sing["inbounds"] if item["type"] == "mixed"]
        tun = [item for item in self.sing["inbounds"] if item["type"] == "tun"]
        self.assertEqual(len(mixed), 1)
        self.assertEqual(mixed[0]["listen"], "127.0.0.1")
        self.assertEqual(mixed[0]["listen_port"], 2080)
        self.assertEqual(len(tun), 1)
        self.assertEqual(tun[0]["dns_mode"], "hijack")

    def test_five_rule_sets_match_route_offline_whitelist(self):
        rules = self.sing["route"]["rule_set"]
        self.assertEqual([rule["tag"] for rule in rules], list(PUBLIC_RULE_NAMES))
        for rule in rules:
            self.assertEqual(rule["type"], "remote")
            self.assertEqual(rule["format"], "binary")
            self.assertEqual(rule["url"], public_rule_url(rule["tag"]))
            self.assertEqual(rule["download_detour"], "Default Exit")
            self.assertEqual(rule["update_interval"], "1d")
            self.assertNotIn("initial_path", rule)

    def test_export_removes_only_machine_local_public_rule_seeds(self):
        for rule in self.sing["route"]["rule_set"]:
            rule["initial_path"] = "machine-only/public-rule.srs"
        custom = {"type": "remote", "tag": "custom", "format": "binary", "url": "https://example.invalid/custom.srs", "initial_path": "preserve-custom-seed.srs"}
        self.sing["route"]["rule_set"].append(custom)
        rendered = json.loads(serialize_profile(self.sing))
        self.assertTrue(all("initial_path" not in rule for rule in rendered["route"]["rule_set"][:-1]))
        self.assertEqual(rendered["route"]["rule_set"][-1], custom)

    def test_changed_public_url_is_not_rewritten(self):
        rule = self.sing["route"]["rule_set"][0]
        rule.update(url="https://example.invalid/private.srs", initial_path="custom.srs")
        self.assertEqual(json.loads(serialize_profile(self.sing))["route"]["rule_set"][0]["initial_path"], "custom.srs")

    def test_size_limit_counts_utf8_bytes(self):
        self.assertGreater(len("中文".encode("utf-8")), len("中文"))
        oversized = {"comment": "中" * (MAX_PROFILE_BYTES // 3)}
        with self.assertRaisesRegex(SystemExit, "smaller than 4 MiB"):
            serialize_profile(oversized)
        self.assertLess(len(serialize_profile(self.sing).encode("utf-8")), MAX_PROFILE_BYTES)

    def test_dns_and_download_detours_are_validated(self):
        for kind in ("dns", "download", "dns_rule", "dns_final"):
            value = copy.deepcopy(self.sing)
            if kind == "dns":
                value["dns"]["servers"][-1]["detour"] = "Missing"
            elif kind == "download":
                value["route"]["rule_set"][0]["download_detour"] = "Missing"
            elif kind == "dns_rule":
                value["dns"]["rules"][0]["server"] = "Missing"
            else:
                value["dns"]["final"] = "Missing"
            with self.subTest(kind=kind), self.assertRaises(SystemExit):
                validate_rendered_references(self.clash, value)

    def test_modes_and_guard_groups_have_real_rules(self):
        routing = self.sing["route"]["rules"]
        self.assertEqual([rule.get("action") for rule in routing[:2]], ["sniff", "hijack-dns"])
        self.assertEqual({rule["clash_mode"] for rule in routing if "clash_mode" in rule}, {"Direct", "Global"})
        routed = {rule.get("outbound") for rule in routing}
        for tag in ("Microsoft Global", "Ad Block", "UDP Guard", "QUIC Guard", "WebRTC Guard", "Direct Route", "Catch-All"):
            self.assertIn(tag, routed)

    def test_compatibility_catalog_separates_client_from_server(self):
        manifest = json.loads((ROOT / "config/versions.json").read_text(encoding="utf-8"))
        self.assertEqual(manifest["sing_box"]["version"], "1.14.2")
        self.assertEqual(manifest["sing_box"]["assets"]["amd64"]["name"], "sing-box-1.14.2-linux-amd64.tar.gz")
        self.assertEqual(manifest["sing_box"]["assets"]["windows_amd64"]["version"], "1.14.2")
        self.assertEqual(manifest["client_compatibility"]["may_route"]["version"], "1.14.2-mxh.7")


if __name__ == "__main__":
    unittest.main(verbosity=2)
