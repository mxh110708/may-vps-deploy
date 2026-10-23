from __future__ import annotations

import copy
import json
import sys
import unittest
from pathlib import Path

from ruamel.yaml import YAML

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from academic_client_policy import apply_academic_clash, apply_academic_sing, load_academic_policy
from test_google_client_policy import clash_target, domain_match, sing_target


class AcademicClientPolicyTests(unittest.TestCase):
    def setUp(self):
        self.clash = YAML(typ="safe").load((ROOT / "templates/client/clash-general.template.yaml").read_text())
        self.sing = json.loads((ROOT / "templates/client/sing-box-general.template.json").read_text())

    def test_school_and_domestic_library_access_stays_direct_even_if_direct_selector_uses_proxy(self):
        for document, key, name, members in [(self.clash, "proxy-groups", "name", "proxies"), (self.sing, "outbounds", "tag", "outbounds")]:
            group = next(g for g in document[key] if g.get(name) == "Direct Route")
            if "Default Exit" not in group[members]:
                group[members].append("Default Exit")
            group["default"] = "Default Exit"
            self.assertIn("Default Exit", group[members])
        hosts = ["sysu.co.cnki.net", "cas.sysu.edu.cn", "portal.sysu.edu.cn", "library-443.webvpn.sysu.edu.cn",
                 "kns.cnki.net", "reportdownload.cnki.net", "login.example.edu.cn", "intranet.example.ac.cn",
                 "www.wanfangdata.com.cn", "www.cqvip.com", "www.duxiu.com", "www.chaoxing.com"]
        for host in hosts:
            with self.subTest(host=host):
                self.assertEqual(clash_target(self.clash, host), "DIRECT")
                self.assertEqual(sing_target(self.sing, host), "DIRECT")
                rule = next(r for r in self.sing["dns"]["rules"] if domain_match(r, host))
                self.assertEqual(next(s["type"] for s in self.sing["dns"]["servers"] if s["tag"] == rule["server"]), "local")
        self.assertIn("+.edu.cn", self.clash["dns"]["fake-ip-filter"])
        self.assertEqual(self.clash["dns"]["nameserver-policy"]["+.edu.cn"], ["system"])

    def test_search_login_fulltext_and_download_domains_share_the_research_selector(self):
        hosts = ["scholar.google.com", "scholar.google.com.hk", "scholar.google.co.jp", "scholar.google.com.sg",
                 "colab.research.google.com", "www.kaggle.com", "storage.kaggleusercontent.com", "www.sciencedirect.com",
                 "id.elsevier.com", "pdf.sciencedirectassets.com", "cdn.els-cdn.com", "www.scopus.com",
                 "www.webofscience.com", "webofscience.clarivate.cn", "link.springernature.com", "media.springernature.com",
                 "onlinelibrary.wiley.com", "ieeexplore.ieee.org", "dl.acm.org", "research.ebsco.com", "search.ebscohost.com",
                 "www.proquest.com", "pubmed.ncbi.nlm.nih.gov", "pmc.ncbi.nlm.nih.gov", "doi.org", "login.openathens.net",
                 "cas-bridge.xethub.hf.co", "demo.hf.space", "signin.ebsco.zone", "content.ebsco-content.com",
                 "www.cochranelibrary.com", "aclanthology.org"]
        for host in hosts:
            with self.subTest(host=host):
                self.assertEqual(clash_target(self.clash, host), "Academic Research")
                self.assertEqual(sing_target(self.sing, host), "Academic Research")
                dns = next(r for r in self.sing["dns"]["rules"] if domain_match(r, host))
                self.assertEqual(next(s["type"] for s in self.sing["dns"]["servers"] if s["tag"] == dns["server"]), "fakeip")

    def test_suffix_boundaries_and_shared_clouds_do_not_expand_the_category(self):
        for host in ["sysu.edu.cn.example.invalid", "evilcnki.net", "scholar.google.com.evil.example", "scholar.evil.example",
                     "unrelated.s3.amazonaws.com", "shared.cloudfront.net", "unrelated.azureedge.net"]:
            self.assertNotIn(clash_target(self.clash, host), ["DIRECT", "Academic Research"])
            self.assertNotIn(sing_target(self.sing, host), ["DIRECT", "Academic Research"])
        for host, group in [("gemini.google.com", "AI Services"), ("chatgpt.com", "AI Services"),
                            ("accounts.google.com", "Google Services"), ("docs.google.com", "Google Services"),
                            ("www.youtube.com", "Google Services"), ("github.com", "Developer Tools"), ("netflix.com", "Streaming Media")]:
            self.assertEqual(clash_target(self.clash, host), group)
            self.assertEqual(sing_target(self.sing, host), group)

    def test_research_websites_and_framework_documentation_are_not_ai_inference_services(self):
        for host, group in [("deepmind.google", "Academic Research"), ("research.google", "Academic Research"),
                            ("openxla.org", "Developer Tools"), ("www.tensorflow.org", "Developer Tools"),
                            ("pytorch.org", "Developer Tools"), ("keras.io", "Developer Tools")]:
            self.assertEqual(clash_target(self.clash, host), group)
            self.assertEqual(sing_target(self.sing, host), group)

    def test_repeat_application_keeps_selectors_credentials_and_dns_servers(self):
        c, s = copy.deepcopy(self.clash), copy.deepcopy(self.sing)
        apply_academic_clash(c); apply_academic_sing(s)
        self.assertEqual(c, self.clash)
        self.assertEqual(s, self.sing)
        self.assertEqual(c["proxy-groups"], self.clash["proxy-groups"])
        self.assertEqual(s["outbounds"], self.sing["outbounds"])
        self.assertEqual(s["dns"]["servers"], self.sing["dns"]["servers"])

    def test_explicit_modes_and_protocol_controls_still_precede_business_rules(self):
        s = copy.deepcopy(self.sing)
        controls = [{"clash_mode": "Direct", "action": "route", "outbound": "DIRECT"},
                    {"clash_mode": "Global", "action": "route", "outbound": "Default Exit"},
                    {"protocol": "dns", "action": "hijack-dns"},
                    {"network": "udp", "port": [443], "action": "route", "outbound": "QUIC Guard"}]
        s["route"]["rules"] = controls + s["route"]["rules"]
        apply_academic_sing(s)
        self.assertEqual(s["route"]["rules"][:len(controls)], controls)

    def test_no_second_system_or_fakeip_resolver_and_no_unsafe_tag_collision(self):
        s = copy.deepcopy(self.sing)
        for server in s["dns"]["servers"]:
            if server["type"] == "local": server["tag"] = "campus-owner-dns"
            if server["type"] == "fakeip": server["tag"] = "owner-fakeip"
        before = copy.deepcopy(s["dns"]["servers"])
        apply_academic_sing(s)
        self.assertEqual(s["dns"]["servers"], before)
        self.assertEqual(next(r["server"] for r in s["dns"]["rules"] if domain_match(r, "cas.sysu.edu.cn")), "campus-owner-dns")
        collision = copy.deepcopy(self.sing)
        collision["dns"]["servers"] = [{"type": "local", "tag": "dns-business-fakeip"}]
        with self.assertRaisesRegex(ValueError, "occupied"):
            apply_academic_sing(collision)

    def test_catalog_is_bounded_and_does_not_route_all_foreign_universities_or_clouds(self):
        policy = load_academic_policy()
        self.assertNotIn("edu", policy["campus_direct_suffixes"])
        self.assertNotIn("amazonaws.com", policy["research_suffixes"])
        self.assertNotIn("cloudfront.net", policy["research_suffixes"])
        self.assertLess(len(policy["research_suffixes"]), 200)


if __name__ == "__main__":
    unittest.main()
