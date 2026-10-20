"""Portable May Route profile serialization shared by both candidate builders."""
from __future__ import annotations

import json
from typing import Any

MAX_PROFILE_BYTES = 4 * 1024 * 1024
PUBLIC_RULE_NAMES = (
    "geosite-category-ads-all", "geosite-private", "geosite-cn", "geoip-cn",
    "geosite-geolocation-not-cn",
)


def public_rule_url(name: str) -> str:
    geo = "geoip" if name.startswith("geoip-") else "geosite"
    leaf = name.removeprefix(f"{geo}-").replace("geolocation-not-cn", "geolocation-!cn")
    return f"https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/sing/geo/{geo}/{leaf}.srs"


def serialize_profile(document: dict[str, Any]) -> str:
    # GUI import/export uses this exact whitelist. Custom initial_path semantics
    # are not ours to rewrite; only remove stale machine-local public-rule seeds.
    for rule in (document.get("route") or {}).get("rule_set") or []:
        name = rule.get("tag")
        if (name in PUBLIC_RULE_NAMES and rule.get("type") == "remote"
                and rule.get("format") == "binary" and rule.get("url") == public_rule_url(name)):
            rule.pop("initial_path", None)
    text = json.dumps(document, ensure_ascii=False, separators=(",", ":")) + "\n"
    if len(text.encode("utf-8")) >= MAX_PROFILE_BYTES:
        raise SystemExit("May Route profile must be smaller than 4 MiB; no oversized candidate was written")
    return text
