#!/usr/bin/env python3
"""Build Clash and sing-box authority candidates from a private layout specification.

The source authority files are read-only. The specification may contain active
credentials and must stay in a local private directory.
"""
from __future__ import annotations

import argparse
import copy
import json
from pathlib import Path
from typing import Any

from ruamel.yaml import YAML
from client_compatibility import serialize_profile
from google_client_policy import apply_clash, apply_sing, load_policy, ordered_google_group


ROLE_FILES = {
    "RealityEntry": ("mihomo-test-primary.yaml", "sing-box-outbounds.private.json"),
    "AnyTlsEntry": ("mihomo-anytls-test.yaml", "sing-box-anytls-outbounds.private.json"),
    "ShadowsocksLanding": ("mihomo-shadowsocks-test.yaml", "sing-box-shadowsocks-outbounds.private.json"),
}


def fail(message: str) -> None:
    raise SystemExit(message)


def load_fragment(source: dict[str, Any]) -> list[dict[str, Any]]:
    role = str(source.get("role", ""))
    if role not in ROLE_FILES:
        fail(f"unsupported fragment role: {role}")
    directory = Path(str(source.get("fragment_dir", "")))
    yaml_name, json_name = ROLE_FILES[role]
    yaml_path, json_path = directory / yaml_name, directory / json_name
    if not yaml_path.is_file() or not json_path.is_file():
        fail(f"missing client exports for {role}: {directory}")
    yaml = YAML(typ="safe")
    clash_nodes = (yaml.load(yaml_path.read_text(encoding="utf-8")) or {}).get("proxies") or []
    sing_nodes = json.loads(json_path.read_text(encoding="utf-8")).get("outbounds") or []
    clash_by_name = {str(item.get("name")): item for item in clash_nodes}
    sing_by_name = {str(item.get("tag")): item for item in sing_nodes}
    selected = source.get("node_names") or sorted(set(clash_by_name) & set(sing_by_name))
    result: list[dict[str, Any]] = []
    for name in selected:
        if name not in clash_by_name or name not in sing_by_name:
            fail(f"fragment node is not present in both clients: {name}")
        result.append({
            "name": name,
            "kind": "landing" if role == "ShadowsocksLanding" else "entry",
            "region_group": source.get("region_group"),
            "transit_group": source.get("transit_group"),
            "clash": copy.deepcopy(clash_by_name[name]),
            "sing_box": copy.deepcopy(sing_by_name[name]),
            "origin": str(directory),
        })
    return result


def collect_nodes(spec: dict[str, Any], clash: dict[str, Any], sing: dict[str, Any]) -> list[dict[str, Any]]:
    formats = set(spec.get("client_formats", ["Clash", "SingBox"]))
    nodes: list[dict[str, Any]] = []
    for source in spec.get("fragment_sources") or []:
        nodes.extend(load_fragment(source))
    nodes.extend(copy.deepcopy(spec.get("manual_nodes") or []))
    clash_existing = {str(item.get("name")): item for item in clash.get("proxies") or []}
    sing_existing = {str(item.get("tag")): item for item in sing.get("outbounds") or []}
    for reference in spec.get("existing_node_refs") or []:
        name = str(reference.get("name", ""))
        if ("Clash" in formats and name not in clash_existing) or ("SingBox" in formats and name not in sing_existing):
            fail(f"existing authority node is missing in a selected client: {name}")
        nodes.append({
            "name": name,
            "kind": reference.get("kind"),
            "region_group": reference.get("region_group"),
            "transit_group": reference.get("transit_group"),
            "clash": copy.deepcopy(clash_existing.get(name)),
            "sing_box": copy.deepcopy(sing_existing.get(name)),
            "origin": "existing-authority",
        })
    seen: set[str] = set()
    for node in nodes:
        name = str(node.get("name", ""))
        if not name or name in seen:
            fail(f"empty or duplicate node name: {name!r}")
        seen.add(name)
        if "Clash" in formats and str((node.get("clash") or {}).get("name", "")) != name:
            fail(f"Clash node name mismatch: {name}")
        if "SingBox" in formats and str((node.get("sing_box") or {}).get("tag", "")) != name:
            fail(f"sing-box node tag mismatch: {name}")
        kind = str(node.get("kind", ""))
        if kind == "entry":
            if not node.get("region_group"):
                fail(f"entry node has no region group: {name}")
        elif kind == "landing":
            transit = str(node.get("transit_group", ""))
            if not transit:
                fail(f"landing node has no transit group: {name}")
            if "Clash" in formats:
                node["clash"]["dialer-proxy"] = transit
            if "SingBox" in formats:
                node["sing_box"]["detour"] = transit
        else:
            fail(f"invalid node kind for {name}: {kind}")
    return nodes


def replace_named(items: list[dict[str, Any]], key: str, replacements: list[dict[str, Any]], removed: set[str] | None = None) -> list[dict[str, Any]]:
    names = {str(item[key]) for item in replacements} | (removed or set())
    existing = [item for item in items if str(item.get(key, "")) not in names]
    return existing + copy.deepcopy(replacements)


def update_node_references(document: dict[str, Any], removed: set[str], renamed: dict[str, str], client: str, strict_defaults: bool = False) -> None:
    # Preserve custom groups, while removing/renaming their references to nodes
    # explicitly owned by this editor. Unrelated nodes and settings stay intact.
    groups = document.get("proxy-groups" if client == "clash" else "outbounds") or []
    for group in groups:
        if client != "clash" and group.get("type") not in {"selector", "urltest"}:
            continue
        key = "proxies" if client == "clash" else "outbounds"
        if key not in group:
            continue
        group[key] = [renamed.get(str(name), str(name)) for name in group[key] if str(name) not in removed or str(name) in renamed]
        if not group[key]:
            fail("removing nodes would empty an existing group; edit its members first")
        if "default" in group:
            value = str(group["default"])
            if strict_defaults and value in removed and value not in renamed:
                fail("ClientOutputDefaultRemoved: choose the retained group default before generating")
            group["default"] = renamed.get(value, value) if value not in removed or value in renamed else group[key][0]
    def rename(value: Any) -> None:
        if isinstance(value, dict):
            for key, item in list(value.items()):
                if (key in {"outbound", "detour", "dialer-proxy"} or key == "final" and value is document.get("route")) and isinstance(item, str):
                    value[key] = renamed.get(item, item)
                elif key == "download_detour" and isinstance(item, str):
                    value[key] = renamed.get(item, item)
                else:
                    rename(item)
        elif isinstance(value, list):
            for item in value:
                rename(item)
    rename(document)
    if client == "clash":
        rule_lists = [document.get("rules") or [], *(document.get("sub-rules") or {}).values()]
        for rules in rule_lists:
            for index, rule in enumerate(rules):
                if not isinstance(rule, str):
                    continue
                parts = rule.rsplit(",", 2)
                target = -2 if parts[-1].strip() == "no-resolve" else -1
                if len(parts) < 2:
                    continue
                name = parts[target].strip()
                if name in renamed:
                    parts[target] = renamed[name]
                    rules[index] = ",".join(parts)
                elif name in removed:
                    fail("a retained Clash rule uses a removed node; update its target first")


def normalize_members(members: list[Any], client: str) -> list[str]:
    result: list[str] = []
    for value in members:
        name = str(value)
        if client == "clash" and name == "BLOCK":
            name = "REJECT"
        elif client == "sing_box" and name == "REJECT":
            name = "BLOCK"
        if name not in result:
            result.append(name)
    return result


def apply_clash_groups(document: dict[str, Any], groups: list[dict[str, Any]], order: list[str], remove: set[str]) -> None:
    current = [item for item in list(document.get("proxy-groups") or []) if str(item.get("name")) not in remove]
    by_name = {str(item.get("name")): item for item in current}
    for definition in groups:
        name = str(definition["name"])
        item = by_name.get(name, {"name": name, "type": "select"})
        item["type"] = "select"
        item["proxies"] = normalize_members(list(definition.get("members") or []), "clash")
        by_name[name] = item
    ordered: list[dict[str, Any]] = []
    emitted: set[str] = set()
    for name in order:
        if name in by_name and name not in emitted:
            ordered.append(by_name[name]); emitted.add(name)
    for item in current:
        name = str(item.get("name"))
        if name not in emitted:
            ordered.append(by_name[name]); emitted.add(name)
    for definition in groups:
        name = str(definition["name"])
        if name not in emitted:
            ordered.append(by_name[name]); emitted.add(name)
    document["proxy-groups"] = ordered


def apply_sing_groups(document: dict[str, Any], groups: list[dict[str, Any]], order: list[str], remove: set[str]) -> None:
    generated = {str(item['name']) for item in groups}
    outbounds = [item for item in list(document.get("outbounds") or [])
                 if not (item.get("type") in {"selector", "urltest"} and str(item.get("tag")) in remove)]
    selectors = {str(item.get("tag")): item for item in outbounds if item.get("type") == "selector"}
    non_selectors = [item for item in outbounds if item.get("type") != "selector"
                     and not (item.get("type") == "urltest" and str(item.get("tag")) in generated)]
    for definition in groups:
        name = str(definition["name"])
        item = selectors.get(name, {"type": "selector", "tag": name})
        item["type"] = "selector"
        item["tag"] = name
        item["outbounds"] = normalize_members(list(definition.get("members") or []), "sing_box")
        item["default"] = item["outbounds"][0]
        selectors[name] = item
    ordered: list[dict[str, Any]] = []
    emitted: set[str] = set()
    for name in order:
        if name in selectors and name not in emitted:
            ordered.append(selectors[name]); emitted.add(name)
    for item in outbounds:
        if item.get("type") == "selector":
            name = str(item.get("tag"))
            if name not in emitted:
                ordered.append(selectors[name]); emitted.add(name)
    for definition in groups:
        name = str(definition["name"])
        if name not in emitted:
            ordered.append(selectors[name]); emitted.add(name)
    document["outbounds"] = non_selectors + ordered


def validate_group_graph(groups: list[dict[str, Any]], node_names: set[str]) -> None:
    group_names = {str(item["name"]) for item in groups}
    builtins = {"DIRECT", "REJECT", "BLOCK"}
    graph: dict[str, list[str]] = {}
    for group in groups:
        name = str(group["name"])
        members = [str(item) for item in group.get("members") or []]
        if not members:
            fail(f"selector group has no members: {name}")
        missing = [item for item in members if item not in node_names and item not in group_names and item not in builtins]
        if missing:
            fail(f"group {name} references unknown members: {', '.join(missing)}")
        graph[name] = [item for item in members if item in group_names]
    visiting: set[str] = set()
    visited: set[str] = set()
    def visit(name: str) -> None:
        if name in visiting:
            fail(f"selector cycle detected at: {name}")
        if name in visited:
            return
        visiting.add(name)
        for child in graph.get(name, []):
            visit(child)
        visiting.remove(name); visited.add(name)
    for name in graph:
        visit(name)


def validate_rendered_references(clash: dict[str, Any], sing: dict[str, Any]) -> None:
    clash_nodes = {str(item.get("name")) for item in clash.get("proxies") or []}
    clash_groups = {str(item.get("name")) for item in clash.get("proxy-groups") or []}
    for group in clash.get("proxy-groups") or []:
        missing = [str(item) for item in group.get("proxies") or []
                   if str(item) not in clash_nodes and str(item) not in clash_groups and str(item) not in {"DIRECT", "REJECT"}]
        if missing:
            fail(f"rendered Clash group {group.get('name')} has unknown members: {', '.join(missing)}")
    sing_tags = {str(item.get("tag")) for item in sing.get("outbounds") or []}
    for outbound in sing.get("outbounds") or []:
        if outbound.get("type") == "selector":
            missing = [str(item) for item in outbound.get("outbounds") or [] if str(item) not in sing_tags]
            if missing:
                fail(f"rendered sing-box selector {outbound.get('tag')} has unknown members: {', '.join(missing)}")
        detour = outbound.get("detour")
        if detour and str(detour) not in sing_tags:
            fail(f"rendered sing-box outbound {outbound.get('tag')} has unknown detour: {detour}")
    route = sing.get("route") or {}
    final = route.get("final")
    if final and str(final) not in sing_tags:
        fail(f"rendered sing-box route has unknown final outbound: {final}")
    def check_route_rules(value: Any) -> None:
        if isinstance(value, dict):
            outbound = value.get("outbound")
            if outbound and str(outbound) not in sing_tags:
                fail(f"rendered sing-box route rule has unknown outbound: {outbound}")
            for child in value.values():
                check_route_rules(child)
        elif isinstance(value, list):
            for child in value:
                check_route_rules(child)
    check_route_rules(route.get("rules") or [])
    for rule in route.get("rule_set") or []:
        detour = rule.get("download_detour")
        if detour and str(detour) not in sing_tags:
            fail("rendered sing-box rule set has an unknown download detour")
    dns = sing.get("dns") or {}
    dns_tags = {str(server.get("tag")) for server in dns.get("servers") or []}
    for server in dns.get("servers") or []:
        detour = server.get("detour")
        if detour and str(detour) not in sing_tags:
            fail("rendered sing-box DNS server has an unknown detour")
    def check_dns_rules(value: Any) -> None:
        if isinstance(value, dict):
            server = value.get("server")
            if server and str(server) not in dns_tags:
                fail("rendered sing-box DNS rule has an unknown server")
            for child in value.values():
                check_dns_rules(child)
        elif isinstance(value, list):
            for child in value:
                check_dns_rules(child)
    check_dns_rules(dns.get("rules") or [])
    if dns.get("final") and str(dns["final"]) not in dns_tags:
        fail("rendered sing-box DNS has an unknown final server")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--clash", type=Path)
    parser.add_argument("--sing-box", type=Path)
    parser.add_argument("--spec", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    spec = json.loads(args.spec.read_text(encoding="utf-8"))
    if int(spec.get("schema_version", 0)) != 1:
        fail("unsupported client layout spec schema")
    formats = spec.get("client_formats", ["Clash", "SingBox"])
    if not isinstance(formats, list) or not formats or len(set(formats)) != len(formats) or set(formats) - {"Clash", "SingBox"}:
        fail("unsupported client selection")
    if ("Clash" in formats and args.clash is None) or ("SingBox" in formats and args.sing_box is None):
        fail("selected client source is required")
    yaml = YAML()
    yaml.preserve_quotes = True
    yaml.width = 4096
    clash: dict[str, Any] = {}
    sing: dict[str, Any] = {}
    if "Clash" in formats:
        with args.clash.open("r", encoding="utf-8") as handle:
            clash = yaml.load(handle)
    if "SingBox" in formats:
        sing = json.loads(args.sing_box.read_text(encoding="utf-8"))
    if spec.get("source_mode") == "GenericTemplate":
        policy = load_policy()
        if "Clash" in formats:
            apply_clash(clash, policy)
        if "SingBox" in formats:
            apply_sing(sing, policy)
    nodes = collect_nodes(spec, clash, sing)
    groups = copy.deepcopy(spec.get("groups") or [])
    order = [str(value) for value in spec.get("group_order") or []]
    remove_groups = {str(value) for value in spec.get("remove_groups") or []}
    remove_nodes = {str(value) for value in spec.get("remove_nodes") or []}
    rename_nodes = {str(key): str(value) for key, value in (spec.get("rename_nodes") or {}).items()}
    if remove_nodes & {str(node["name"]) for node in nodes} or set(rename_nodes) - remove_nodes:
        fail("invalid removed or renamed node ownership")
    if remove_groups & {str(group["name"]) for group in groups}:
        fail("a selector cannot be both generated and removed")
    validate_group_graph(groups, {str(node["name"]) for node in nodes})
    if "Clash" in formats:
        clash_nodes = [copy.deepcopy(node["clash"]) for node in nodes]
        clash["proxies"] = replace_named(list(clash.get("proxies") or []), "name", clash_nodes, remove_nodes)
        apply_clash_groups(clash, groups, order, remove_groups)
        update_node_references(clash, remove_nodes, rename_nodes, "clash", bool(spec.get("strict_removed_defaults")))
    if "SingBox" in formats:
        sing_nodes = [copy.deepcopy(node["sing_box"]) for node in nodes]
        sing["outbounds"] = replace_named(list(sing.get("outbounds") or []), "tag", sing_nodes, remove_nodes)
        apply_sing_groups(sing, groups, order, remove_groups)
        update_node_references(sing, remove_nodes, rename_nodes, "sing_box", bool(spec.get("strict_removed_defaults")))
    if spec.get("source_mode") == "GenericTemplate":
        if "Clash" in formats:
            ordered_google_group(clash["proxy-groups"], "name", {})
        if "SingBox" in formats:
            ordered_google_group(sing["outbounds"], "tag", {})
    validate_rendered_references(clash, sing)

    args.output.mkdir(parents=True, exist_ok=True)
    if "Clash" in formats:
        with (args.output / "Clash_General.candidate.yaml").open("w", encoding="utf-8", newline="\n") as handle:
            yaml.dump(clash, handle)
    if "SingBox" in formats:
        # The desktop IPC path has a practical 4 MiB ceiling.
        (args.output / "sing-box-general.candidate.json").write_text(serialize_profile(sing), encoding="utf-8")
    manifest = {
        "schema_version": 1,
        "generated_nodes": [str(node["name"]) for node in nodes],
        "groups": [str(group["name"]) for group in groups],
        "removed_groups": sorted(remove_groups),
        "authoritative_files_modified": False,
        "source_mode": str(spec.get("source_mode", "unspecified")),
        "requested_output_mode": str(spec.get("output_mode", "unspecified")),
        "client_formats": formats,
        "source_clash": str(args.clash) if "Clash" in formats else None,
        "source_sing_box": str(args.sing_box) if "SingBox" in formats else None,
    }
    (args.output / "candidate-manifest.json").write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )


if __name__ == "__main__":
    main()
