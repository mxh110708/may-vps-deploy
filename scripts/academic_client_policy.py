"""Campus access, scholarly services and ML tooling category boundaries.

This is a build-time policy. It never changes a user's selector choices or starts
a client. ExistingAuthority sources are still edited only by an explicit action.
"""
from __future__ import annotations

import copy
import json
import re
from pathlib import Path
from typing import Any

RESEARCH = "Academic Research"
FIELDS = ("domain", "domain_suffix", "domain_keyword", "domain_regex")
TYPES = dict(zip(FIELDS, ("DOMAIN", "DOMAIN-SUFFIX", "DOMAIN-KEYWORD", "DOMAIN-REGEX")))


def load_academic_policy() -> dict[str, Any]:
    policy = json.loads((Path(__file__).resolve().parents[1] / "config/academic-services.policy.json").read_text(encoding="utf-8"))
    if policy.get("schema_version") != 1:
        raise ValueError("Unsupported academic policy schema")
    for field in ("campus_direct_suffixes", "research_suffixes", "scholar_google_bases", "developer_suffixes"):
        values = policy[field]
        if len(values) != len(set(values)) or any(not re.fullmatch(r"[a-z0-9-]+(?:\.[a-z0-9-]+)+", value) for value in values):
            raise ValueError("Invalid academic domain catalog")
    return policy


def academic_matches(policy: dict[str, Any]) -> tuple[dict[str, list[str]], dict[str, list[str]]]:
    return ({"domain_suffix": list(policy["campus_direct_suffixes"])},
            {"domain_suffix": list(policy["research_suffixes"]) + ["scholar." + base for base in policy["scholar_google_bases"]]})


def _covered(name: str, suffixes: list[str]) -> bool:
    return any(name == suffix or name.endswith("." + suffix) for suffix in suffixes)


def _without_owned(rule: dict[str, Any], owned: list[str]) -> dict[str, Any] | None:
    result = copy.deepcopy(rule)
    if result.get("type", "default") != "default" or result.get("invert"):
        return result
    removed = False
    for field in ("domain", "domain_suffix"):
        values = result.get(field)
        if values is None:
            continue
        entries = [values] if isinstance(values, str) else values
        remaining = [name for name in entries if not _covered(name, owned)]
        if len(remaining) != len(entries):
            removed = True
            if remaining:
                result[field] = remaining
            else:
                result.pop(field)
    # A former domain+port rule must not become an unconditional port rule.
    if removed and not any(result.get(field) for field in (*FIELDS, "ip_cidr", "ip_is_private", "rule_set")):
        return None
    return result


def apply_academic_clash(document: dict[str, Any], policy: dict[str, Any] | None = None) -> None:
    policy = policy or load_academic_policy()
    groups = document.get("proxy-groups", [])
    if not any(group.get("name") == RESEARCH for group in groups):
        raise ValueError("Academic policy requires Academic Research")
    direct, research = academic_matches(policy)
    developer = {"domain_suffix": list(policy["developer_suffixes"])}
    if not any(group.get("name") == "Developer Tools" for group in groups):
        raise ValueError("Academic policy requires Developer Tools for ML documentation")
    owned = direct["domain_suffix"] + research["domain_suffix"] + developer["domain_suffix"]
    kept = []
    for rule in document.get("rules", []):
        parts = str(rule).split(",")
        if len(parts) == 3 and parts[0] in ("DOMAIN", "DOMAIN-SUFFIX") and _covered(parts[1], owned):
            continue
        kept.append(rule)
    business = {group.get("name") for group in groups} - {"Direct Route", "Legacy Ports", "QUIC Guard", "WebRTC Guard"}
    index = next((i for i, rule in enumerate(kept) if str(rule).split(",")[-1] in business or str(rule).startswith(("GEOSITE,cn,", "MATCH,"))), len(kept))
    early = [f"DOMAIN-SUFFIX,{suffix},DIRECT" for suffix in direct["domain_suffix"]]
    early += [f"DOMAIN-SUFFIX,{suffix},{RESEARCH}" for suffix in research["domain_suffix"]]
    early += [f"DOMAIN-SUFFIX,{suffix},Developer Tools" for suffix in developer["domain_suffix"]]
    kept[index:index] = early
    document["rules"] = kept
    dns = document.setdefault("dns", {})
    if dns.get("fake-ip-filter-mode", "blacklist") != "blacklist":
        raise ValueError("Campus policy requires a blacklist FakeIP filter")
    filters = dns.setdefault("fake-ip-filter", [])
    for suffix in direct["domain_suffix"]:
        name = "+." + suffix
        if name not in filters:
            filters.append(name)
        dns.setdefault("nameserver-policy", {})[name] = ["system"]
    if dns.get("direct-nameserver"):
        dns["direct-nameserver-follow-policy"] = True


def apply_academic_sing(document: dict[str, Any], policy: dict[str, Any] | None = None) -> None:
    policy = policy or load_academic_policy()
    groups = document.get("outbounds", [])
    if not any(group.get("tag") == RESEARCH for group in groups):
        raise ValueError("Academic policy requires Academic Research")
    direct, research = academic_matches(policy)
    developer = {"domain_suffix": list(policy["developer_suffixes"])}
    if not any(group.get("tag") == "Developer Tools" for group in groups):
        raise ValueError("Academic policy requires Developer Tools for ML documentation")
    owned = direct["domain_suffix"] + research["domain_suffix"] + developer["domain_suffix"]
    route = document.setdefault("route", {})
    kept = []
    for rule in route.get("rules", []):
        value = _without_owned(rule, owned) if rule.get("outbound") else copy.deepcopy(rule)
        if value is not None:
            kept.append(value)
    business = {group.get("tag") for group in groups if group.get("type") == "selector"} - {"Direct Route", "Legacy Ports", "QUIC Guard", "WebRTC Guard"}
    index = next((i for i, rule in enumerate(kept) if not rule.get("clash_mode") and
                  (rule.get("outbound") in business or "geosite-cn" in rule.get("rule_set", []))), len(kept))
    kept[index:index] = [dict(direct, action="route", outbound="DIRECT"), dict(research, action="route", outbound=RESEARCH),
                         dict(developer, action="route", outbound="Developer Tools")]
    route["rules"] = kept
    dns = document.setdefault("dns", {})
    servers = dns.setdefault("servers", [])
    local = next((server["tag"] for server in servers if server.get("type") == "local"), None)
    if local is None:
        local = "dns-campus-local"
        if any(server.get("tag") == local for server in servers):
            raise ValueError("Campus DNS tag is occupied")
        servers.append({"type": "local", "tag": local})
    fake = next((server["tag"] for server in servers if server.get("type") == "fakeip" and server.get("tag") == "dns-business-fakeip"), None)
    fake = fake or next((server["tag"] for server in servers if server.get("type") == "fakeip"), None)
    if fake is None:
        fake = "dns-business-fakeip"
        if any(server.get("tag") == fake for server in servers):
            raise ValueError("Academic FakeIP tag is occupied")
        servers.append({"type": "fakeip", "tag": fake, "inet4_range": "198.18.0.0/15", "inet6_range": "fc00::/18"})
    kept_dns = []
    for rule in dns.get("rules", []):
        value = _without_owned(rule, owned)
        if value is not None:
            kept_dns.append(value)
    def private_dns(rule: dict[str, Any]) -> bool:
        domains = rule.get("domain", [])
        domains = [domains] if isinstance(domains, str) else domains
        return rule.get("rule_set") == ["geosite-private"] or bool(domains) and all("." not in name for name in domains)
    index = next((i for i, rule in enumerate(kept_dns) if not rule.get("clash_mode") and not private_dns(rule)), len(kept_dns))
    fake_matches = {"domain_suffix": research["domain_suffix"] + developer["domain_suffix"]}
    kept_dns[index:index] = [dict(direct, action="route", server=local), dict(fake_matches, query_type=["A"], action="route", server=fake)]
    dns["rules"] = kept_dns
