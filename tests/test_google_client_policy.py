from __future__ import annotations

import copy
import json
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from ruamel.yaml import YAML

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from google_client_policy import apply_clash, apply_sing, load_policy, apply_hugging_face_clash, apply_hugging_face_sing


def domain_match(rule, name):
    return name in rule.get("domain", []) or any(name == d or name.endswith("." + d) for d in rule.get("domain_suffix", [])) or any(re.search(pattern, name) for pattern in rule.get("domain_regex", [])) or any(d in name for d in rule.get("domain_keyword", []))


def clash_target(document, name):
    for rule in document["rules"]:
        parts = rule.split(",")
        if parts[0] == "MATCH":
            return parts[-1]
        if len(parts) == 3 and parts[0] in ["DOMAIN", "DOMAIN-SUFFIX", "DOMAIN-KEYWORD", "DOMAIN-REGEX"]:
            field = {"DOMAIN": "domain", "DOMAIN-SUFFIX": "domain_suffix", "DOMAIN-KEYWORD": "domain_keyword", "DOMAIN-REGEX": "domain_regex"}[parts[0]]
            if domain_match({field: [parts[1]]}, name):
                return parts[-1]
    return None


def sing_target(document, name):
    for rule in document["route"]["rules"]:
        if rule.get("outbound") and domain_match(rule, name):
            return rule["outbound"]
    return document["route"]["final"]


class GoogleClientPolicyTests(unittest.TestCase):
    def setUp(self):
        self.clash = YAML(typ="safe").load((ROOT / "templates/client/clash-general.template.yaml").read_text())
        self.sing = json.loads((ROOT / "templates/client/sing-box-general.template.json").read_text())
        self.policy = load_policy()

    def test_classification_and_priority(self):
        cases = {"gemini.google.com": "AI Services", "generativelanguage.googleapis.com": "AI Services", "aiplatform.googleapis.com": "Google Services", "ai.google.dev": "AI Services",
                 "notebooklm.google.com": "AI Services", "jules.google": "AI Services", "www.google.com": "Google Services", "www.google.co.jp": "Google Services",
                 "mail.google.com": "Google Services", "storage.googleapis.com": "Google Services", "youtube.com": "Google Services", "googlevideo.com": "Google Services",
                 "ytimg.com": "Google Services", "openxla.org": "Google Services", "google": "Direct Route", "chrome": "Direct Route", "youtube": "Direct Route",
                 "netflix.com": "Streaming Media", "huggingface.co": "Academic Research", "arxiv.org": "Academic Research", "google.com.evil.example": "Catch-All"}
        for name, target in cases.items():
            with self.subTest(name=name):
                self.assertEqual(clash_target(self.clash, name), target)
                self.assertEqual(sing_target(self.sing, name), target)
        # A retained OpenX advertising keyword must not hide the ML project.
        c = copy.deepcopy(self.clash); c["rules"].insert(0, "DOMAIN-KEYWORD,openx,Ad Block"); apply_clash(c, self.policy)
        self.assertEqual(clash_target(c, "openxla.org"), "Google Services")
        self.assertEqual(clash_target(c, "openx.net"), "Ad Block")

    def test_all_public_domain_matchers(self):
        for matches, target in [(self.policy["google_ai"], "AI Services")] + [(m, "Google Services") for m in self.policy["google_services"]]:
            for field in ("domain", "domain_suffix"):
                for value in matches.get(field, []):
                    for name in [value] + (["policy-test." + value] if field == "domain_suffix" else []):
                        expected = "Direct Route" if name in self.policy["private_bare_names"] else target
                        with self.subTest(name=name):
                            self.assertEqual(clash_target(self.clash, name), expected)
                            self.assertEqual(sing_target(self.sing, name), expected)

    def test_order_defaults_and_idempotence(self):
        for groups, key in [(self.clash["proxy-groups"], "name"), (self.sing["outbounds"], "tag")]:
            names = [g[key] for g in groups]
            self.assertEqual(names.index("Academic Research") + 1, names.index("Google Services"))
            self.assertEqual(names.index("Google Services") + 1, names.index("Microsoft Services"))
        c, s = copy.deepcopy(self.clash), copy.deepcopy(self.sing)
        apply_clash(c, self.policy); apply_sing(s, self.policy)
        self.assertEqual(c, self.clash); self.assertEqual(s, self.sing)
        google = next(g for g in self.sing["outbounds"] if g["tag"] == "Google Services")
        self.assertEqual(google["default"], "Default Exit")

    def test_hugging_face_hub_and_all_redirect_backends_share_research(self):
        hosts = ["huggingface.co", "cdn-lfs.huggingface.co", "hf.co", "us.aws.cdn.hf.co", "us.gcp.cdn.hf.co", "cas-bridge.xethub.hf.co", "cas-server.xethub.hf.co", "cas-server.xethub-eu.hf.co", "transfer.xethub-eu.hf.co", "cdn-lfs-us-1.hf.co", "cdn-lfs-eu-1.hf.co"]
        for name in hosts:
            with self.subTest(name=name):
                self.assertEqual(clash_target(self.clash, name), "Academic Research")
                self.assertEqual(sing_target(self.sing, name), "Academic Research")
                match = next(r for r in self.sing["dns"]["rules"] if domain_match(r, name))
                self.assertEqual(match["server"], "dns-business-fakeip")
        for name in ["huggingface.co.evil.example", "nothf.co", "hf.com", "unrelated.s3.amazonaws.com"]:
            self.assertNotEqual(clash_target(self.clash, name), "Academic Research")
            self.assertNotEqual(sing_target(self.sing, name), "Academic Research")
        self.assertEqual(sing_target(self.sing, "chatgpt.com"), "AI Services")

    def test_hugging_face_change_preserves_nodes_controls_and_unrelated_ai_matchers(self):
        c, s = copy.deepcopy(self.clash), copy.deepcopy(self.sing)
        before_c = copy.deepcopy(c["proxy-groups"]); before_s = copy.deepcopy(s["outbounds"])
        s["route"]["rules"].append({"domain_suffix": ["hf.co", "other-ai.example"], "ip_cidr": ["192.0.2.0/24"], "action": "route", "outbound": "AI Services"})
        s["route"]["rules"].append({"domain_suffix": ["hf.co"], "network": "tcp", "port": [443], "action": "route", "outbound": "AI Services"})
        apply_hugging_face_clash(c); apply_hugging_face_sing(s)
        self.assertEqual(c["proxy-groups"], before_c); self.assertEqual(s["outbounds"], before_s)
        self.assertTrue(any(r.get("domain_suffix") == ["other-ai.example"] and r.get("ip_cidr") == ["192.0.2.0/24"] for r in s["route"]["rules"]))
        self.assertFalse(any(r.get("outbound") == "AI Services" and "hf.co" in r.get("domain_suffix", []) for r in s["route"]["rules"]))
        self.assertFalse(any(r.get("outbound") == "AI Services" and r.get("network") == "tcp" and r.get("port") == [443] for r in s["route"]["rules"]))
        once_c, once_s = copy.deepcopy(c), copy.deepcopy(s)
        apply_hugging_face_clash(c); apply_hugging_face_sing(s)
        self.assertEqual(c, once_c); self.assertEqual(s, once_s)

    def test_hugging_face_patch_reuses_an_existing_fakeip_server(self):
        s = copy.deepcopy(self.sing)
        for server in s["dns"]["servers"]:
            if server.get("tag") == "dns-business-fakeip": server["tag"] = "owner-fakeip"
        for rule in s["dns"]["rules"]:
            if rule.get("server") == "dns-business-fakeip": rule["server"] = "owner-fakeip"
        servers = copy.deepcopy(s["dns"]["servers"])
        apply_hugging_face_sing(s)
        self.assertEqual(s["dns"]["servers"], servers)
        rule = next(r for r in s["dns"]["rules"] if domain_match(r, "us.aws.cdn.hf.co"))
        self.assertEqual(rule["server"], "owner-fakeip")

    def test_generic_builder_repairs_old_hub_classification(self):
        c, s = copy.deepcopy(self.clash), copy.deepcopy(self.sing)
        c["rules"] = [r.replace(",Academic Research", ",AI Services") if "huggingface.co," in r or ",hf.co," in r else r for r in c["rules"]]
        for r in s["route"]["rules"]:
            if "hf.co" in r.get("domain_suffix", []): r["outbound"] = "AI Services"
        node = {"name":"Fixture", "kind":"entry", "region_group":"Fixture Entry", "clash":{"name":"Fixture", "type":"vless", "server":"192.0.2.20", "port":443, "uuid":"00000000-0000-0000-0000-000000000001"}, "sing_box":{"tag":"Fixture", "type":"vless", "server":"192.0.2.20", "server_port":443, "uuid":"00000000-0000-0000-0000-000000000001"}}
        spec = {"schema_version":1, "source_mode":"GenericTemplate", "manual_nodes":[node], "groups":[{"name":"Fixture Entry", "members":["Fixture"]}], "group_order":["Fixture Entry"]}
        (ROOT / ".tmp").mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(dir=ROOT / ".tmp", prefix="hf-builder-") as d:
            base = Path(d)
            for name, data in [("source.yaml", c), ("source.json", s), ("spec.json", spec)]: (base / name).write_text(json.dumps(data), encoding="utf-8")
            result = subprocess.run([sys.executable, str(ROOT/"scripts/build_client_authority.py"), "--clash", str(base/"source.yaml"), "--sing-box", str(base/"source.json"), "--spec", str(base/"spec.json"), "--output", str(base/"out")], capture_output=True, text=True, timeout=20)
            self.assertEqual(result.returncode, 0, result.stderr)
            clash = YAML(typ="safe").load((base/"out/Clash_General.candidate.yaml").read_text())
            sing = json.loads((base/"out/sing-box-general.candidate.json").read_text())
            for host in ("huggingface.co", "us.aws.cdn.hf.co", "transfer.xethub-eu.hf.co"):
                self.assertEqual(clash_target(clash, host), "Academic Research")
                self.assertEqual(sing_target(sing, host), "Academic Research")

    def test_dns_private_names_and_business_fakeip(self):
        def resolver(name):
            for r in self.sing["dns"]["rules"]:
                if domain_match(r, name):
                    return r["server"]
            return self.sing["dns"]["final"]
        for name in self.policy["private_bare_names"]:
            self.assertEqual(resolver(name), "dns-direct")
            self.assertIn(name, self.clash["dns"]["fake-ip-filter"])
        for name in ["gemini.google.com", "www.google.com", "youtube.com", "chatgpt.com"]:
            self.assertEqual(resolver(name), "dns-business-fakeip")
        private = next(i for i, r in enumerate(self.sing["dns"]["rules"]) if r.get("rule_set") == ["geosite-private"])
        fake = next(i for i, r in enumerate(self.sing["dns"]["rules"]) if r.get("server") == "dns-business-fakeip")
        self.assertLess(private, fake)

    def test_existing_authority_route_and_dns_are_preserved(self):
        c = {"proxies": [], "proxy-groups": [{"name": "Owner", "type": "select", "proxies": ["DIRECT"]}], "rules": ["DOMAIN,gemini.google.com,Owner", "MATCH,DIRECT"], "dns": {"enable": False}}
        s = {"outbounds": [{"type": "direct", "tag": "DIRECT"}, {"type": "selector", "tag": "Owner", "outbounds": ["DIRECT"], "default": "DIRECT"}], "route": {"rules": [{"domain": ["gemini.google.com"], "action": "route", "outbound": "Owner"}], "final": "DIRECT"}, "dns": {"servers": [{"type": "local", "tag": "local"}], "final": "local"}}
        node = {"name": "Fixture", "kind": "entry", "region_group": "Fixture Entry", "clash": {"name": "Fixture", "type": "vless", "server": "192.0.2.20", "port": 443, "uuid": "00000000-0000-0000-0000-000000000001"}, "sing_box": {"tag": "Fixture", "type": "vless", "server": "192.0.2.20", "server_port": 443, "uuid": "00000000-0000-0000-0000-000000000001"}}
        spec = {"schema_version": 1, "source_mode": "ExistingAuthority", "manual_nodes": [node], "groups": [{"name": "Fixture Entry", "members": ["Fixture"]}], "group_order": ["Fixture Entry"]}
        (ROOT / ".tmp").mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(dir=ROOT / ".tmp", prefix="google-policy-") as d:
            base = Path(d)
            for name, data in [("source.yaml", c), ("source.json", s), ("spec.json", spec)]:
                (base / name).write_text(json.dumps(data), encoding="utf-8")
            command = [sys.executable, str(ROOT / "scripts/build_client_authority.py"), "--clash", str(base / "source.yaml"), "--sing-box", str(base / "source.json"), "--spec", str(base / "spec.json"), "--output", str(base / "out")]
            process = subprocess.run(command, capture_output=True, text=True, timeout=20)
            self.assertEqual(process.returncode, 0, process.stderr)
            rendered = YAML(typ="safe").load((base / "out/Clash_General.candidate.yaml").read_text())
            native = json.loads((base / "out/sing-box-general.candidate.json").read_text())
            self.assertEqual(rendered["rules"], c["rules"]); self.assertEqual(rendered["dns"], c["dns"])
            self.assertEqual(native["route"], s["route"]); self.assertEqual(native["dns"], s["dns"])


if __name__ == "__main__":
    unittest.main()
