"""Public Google routing policy shared by the two generic client templates.

Existing authority sources remain owned by the user and are never rewritten here.
The policy contains public domain matchers only, never instance or credential data.
"""
from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any

FIELDS = ("domain", "domain_suffix", "domain_keyword", "domain_regex")
TYPES = dict(zip(FIELDS, ("DOMAIN", "DOMAIN-SUFFIX", "DOMAIN-KEYWORD", "DOMAIN-REGEX")))
AI, GOOGLE = "AI Services", "Google Services"


def load_policy() -> dict[str, Any]:
    data = json.loads((Path(__file__).resolve().parents[1] / "config/google-services.policy.json").read_text(encoding="utf-8"))
    if data.get("schema_version") != 1 or data.get("revision") != "GoogleServices.v1":
        raise ValueError("Unsupported Google client policy")
    return data


def covers(domain: str, matches: dict[str, Any]) -> bool:
    return domain in matches.get("domain", []) or any(domain == d or domain.endswith("." + d) for d in matches.get("domain_suffix", []))


def ordered_google_group(groups: list[dict[str, Any]], key: str, definition: dict[str, Any]) -> None:
    existing = next((g for g in groups if g.get(key) == GOOGLE), None)
    if existing is not None:
        groups.remove(existing)
    item = existing or definition
    index = next((i + 1 for i, g in enumerate(groups) if g.get(key) == "Academic Research"), None)
    if index is None:
        index = next((i for i, g in enumerate(groups) if g.get(key) == "Microsoft Services"), len(groups))
    groups.insert(index, item)


def apply_clash(document: dict[str, Any], policy: dict[str, Any]) -> None:
    google = policy["google_services"]
    ai = policy["google_ai"]
    private = policy["private_bare_names"]
    def rules(matches: dict[str, Any], group: str) -> list[str]:
        return [f"{TYPES[k]},{v},{group}" for k in FIELDS for v in matches.get(k, [])]
    early = [f"DOMAIN,{d},Direct Route" for d in private] + rules(ai, AI)
    early += [r for m in google if m.get("domain_suffix") == ["openxla.org"] for r in rules(m, GOOGLE)]
    broad = [r for m in google if m.get("domain_suffix") != ["openxla.org"] for r in rules(m, GOOGLE)]
    kept = []
    for rule in document.get("rules", []):
        parts = str(rule).split(",")
        if parts[-1] == GOOGLE:
            continue
        if len(parts) == 3:
            kind, domain, group = parts
            if kind == "DOMAIN" and domain in private and group == "Direct Route":
                continue
            if kind in ("DOMAIN", "DOMAIN-SUFFIX") and group == AI and covers(domain, ai):
                continue
            if group == "Streaming Media" and any(covers(domain, m) for m in google):
                continue
        kept.append(rule)
    # Keep control/private rules first, then exceptions before advertising/catch-all.
    first_ad = next((i for i, r in enumerate(kept) if str(r).endswith(",Ad Block")), None)
    first_business = next((i for i, r in enumerate(kept) if str(r).endswith(",AI Services")), len(kept))
    index = first_ad if first_ad is not None else first_business
    kept[index:index] = early
    index = next((i for i, r in enumerate(kept) if str(r).endswith(",Streaming Media") or str(r).startswith("GEOSITE,cn,") or str(r).startswith("MATCH,")), len(kept))
    kept[index:index] = broad
    document["rules"] = kept
    ordered_google_group(document.setdefault("proxy-groups", []), "name", {"name": GOOGLE, "type": "select", "proxies": ["Default Exit", "Direct Route"]})
    dns = document.setdefault("dns", {})
    filters = dns.setdefault("fake-ip-filter", [])
    for name in private:
        if name not in filters:
            filters.append(name)
    policy_map = dns.setdefault("nameserver-policy", {})
    for name in private:
        policy_map[name] = copy.deepcopy(dns.get("direct-nameserver", dns.get("default-nameserver", [])))


def apply_sing(document: dict[str, Any], policy: dict[str, Any]) -> None:
    google = policy["google_services"]
    ai = policy["google_ai"]
    private = policy["private_bare_names"]
    route = document.setdefault("route", {})
    early = [{"domain": copy.deepcopy(private), "action": "route", "outbound": "Direct Route"}, dict(copy.deepcopy(ai), action="route", outbound=AI)]
    early += [dict(copy.deepcopy(m), action="route", outbound=GOOGLE) for m in google if m.get("domain_suffix") == ["openxla.org"]]
    broad = [dict(copy.deepcopy(m), action="route", outbound=GOOGLE) for m in google if m.get("domain_suffix") != ["openxla.org"]]
    kept = []
    for original in route.get("rules", []):
        r = copy.deepcopy(original)
        if r.get("outbound") == GOOGLE:
            continue
        if r.get("outbound") == "Direct Route" and r.get("domain") == private:
            continue
        if r.get("outbound") in (AI, "Streaming Media"):
            for field in FIELDS:
                if field in r:
                    remaining = [d for d in r[field] if not (covers(d, ai) if r["outbound"] == AI else any(covers(d, m) for m in google))]
                    if remaining:
                        r[field] = remaining
                    else:
                        r.pop(field)
            if not any(field in r for field in FIELDS):
                continue
        kept.append(r)
    index = next((i for i, r in enumerate(kept) if r.get("outbound") in ("Ad Block", AI)), len(kept))
    kept[index:index] = early
    index = next((i for i, r in enumerate(kept) if r.get("outbound") == "Streaming Media" or "geosite-cn" in r.get("rule_set", []) or r.get("outbound") == "Catch-All"), len(kept))
    kept[index:index] = broad
    route["rules"] = kept
    ordered_google_group(document.setdefault("outbounds", []), "tag", {"type": "selector", "tag": GOOGLE, "outbounds": ["Default Exit", "Direct Route"], "default": "Default Exit"})
    dns = document.setdefault("dns", {})
    fake = "dns-business-fakeip"
    if not any(server.get("tag") == fake for server in dns.setdefault("servers", [])):
        dns["servers"].append({"type": "fakeip", "tag": fake, "inet4_range": "198.18.0.0/15", "inet6_range": "fc00::/18"})
    original = [r for r in dns.get("rules", []) if r.get("server") != fake and not (r.get("server") == "dns-direct" and (r.get("domain") == private or r.get("rule_set") == ["geosite-private"]))]
    # Private names precede Google TLDs; restore domains through FakeIP for TUN.
    priority = [{"domain": copy.deepcopy(private), "action": "route", "server": "dns-direct"}]
    ai_domains: dict[str, list[str]] = {}
    for field in FIELDS:
        values = list(dict.fromkeys(d for r in route["rules"] if r.get("outbound") == AI for d in r.get(field, [])))
        if values:
            ai_domains[field] = values
    priority.append(dict(ai_domains, query_type=["A"], action="route", server=fake))
    priority.extend(dict(copy.deepcopy(m), query_type=["A"], action="route", server=fake) for m in google)
    index = next((i for i, r in enumerate(original) if r.get("clash_mode") == "Global"), len(original))
    # Split the old combined private/CN rule so Google/AI cannot be hidden by CN.
    private_rule = {"rule_set": ["geosite-private"], "action": "route", "server": "dns-direct"}
    for r in original:
        if r.get("rule_set") == ["geosite-private", "geosite-cn"]:
            r["rule_set"] = ["geosite-cn"]
    priority.insert(0, private_rule)
    original[index:index] = priority
    dns["rules"] = original
