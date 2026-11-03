"""Bounded, read-only native serialization and credential-free export summaries."""
import argparse
import hashlib
import io
import json
import math
import sys
from pathlib import Path
from ruamel.yaml import YAML

LIMIT = 16 * 1024 * 1024


def unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate")
        result[key] = value
    return result


def bounded(value, depth=0, active=None, budget=None):
    if budget is None:
        budget = [200000]
    budget[0] -= 1
    if budget[0] < 0:
        raise ValueError("budget")
    if depth > 64:
        raise ValueError("depth")
    if active is None:
        active = set()
    if isinstance(value, (dict, list)):
        if id(value) in active:
            raise ValueError("cycle")
        active.add(id(value))
        if len(value) > 100000:
            raise ValueError("count")
        children = value.values() if isinstance(value, dict) else value
        if isinstance(value, dict) and any(not isinstance(k, str) for k in value):
            raise ValueError("key")
        for child in children:
            bounded(child, depth + 1, active, budget)
        active.remove(id(value))
    elif isinstance(value, float) and not math.isfinite(value):
        raise ValueError("constant")
    elif value is not None and not isinstance(value, (str, bool, int, float)):
        raise ValueError("type")


def load(path, kind, missing=False):
    target = Path(path).absolute()
    for component in (target, *target.parents):
        if component.is_symlink() or (hasattr(component, "is_junction") and component.is_junction()):
            raise ValueError("link")
    if not target.exists():
        if missing:
            return {}, "missing"
        raise ValueError("missing")
    with target.open("rb") as stream:
        data = stream.read(LIMIT + 1)
    if len(data) > LIMIT:
        raise ValueError("size")
    text = data.decode("utf-8-sig", "strict")
    value = YAML(typ="safe").load(text) if kind == "Clash" else json.loads(text, object_pairs_hook=unique, parse_constant=lambda _: (_ for _ in ()).throw(ValueError("constant")))
    bounded(value)
    if not isinstance(value, dict):
        raise ValueError("root")
    return value, hashlib.sha256(data).hexdigest()


def indexed(value, field):
    if value is None:
        return {}
    if not isinstance(value, list):
        raise ValueError("list")
    result = {}
    for row in value:
        if not isinstance(row, dict) or not isinstance(row.get(field), str) or not row[field] or row[field] in result:
            raise ValueError("identity")
        result[row[field]] = row
    return result


def delta(before, after):
    return {"Added": len(after.keys() - before.keys()), "Removed": len(before.keys() - after.keys()),
            "Changed": sum(before[k] != after[k] for k in before.keys() & after.keys())}


def review(before, after, kind):
    node_key, identity = ("proxies", "name") if kind == "Clash" else ("outbounds", "tag")
    def split(doc):
        nodes = indexed(doc.get(node_key), identity)
        if kind == "Clash":
            return nodes, indexed(doc.get("proxy-groups"), "name")
        return ({k: v for k, v in nodes.items() if v.get("type") not in ("selector", "urltest")},
                {k: v for k, v in nodes.items() if v.get("type") in ("selector", "urltest")})
    old_nodes, old_groups = split(before)
    new_nodes, new_groups = split(after)
    excluded = {node_key, "proxy-groups", "dns", "rules", "rule-providers", "route", "inbounds", "listeners"}
    return {"Nodes": delta(old_nodes, new_nodes), "Groups": delta(old_groups, new_groups),
            "RulesChanged": any(before.get(k) != after.get(k) for k in ("rules", "rule-providers", "route")),
            "DnsChanged": before.get("dns") != after.get("dns"),
            "ListenersChanged": any(before.get(k) != after.get(k) for k in ("inbounds", "listeners")),
            "SettingsChanged": {k: v for k, v in before.items() if k not in excluded} != {k: v for k, v in after.items() if k not in excluded}}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=("review", "fragment"))
    parser.add_argument("--format", choices=("Clash", "SingBox"), required=True)
    parser.add_argument("--before")
    parser.add_argument("--after")
    args = parser.parse_args()
    if args.mode == "review":
        before, old_hash = load(args.before, args.format, True)
        after, new_hash = load(args.after, args.format)
        result = review(before, after, args.format)
        result.update(BeforeHash=old_hash, AfterHash=new_hash)
        output = json.dumps(result, ensure_ascii=True)
    else:
        data = sys.stdin.buffer.read(1024 * 1024 + 1)
        if len(data) > 1024 * 1024:
            raise ValueError("size")
        value = json.loads(data.decode("utf-8"), object_pairs_hook=unique)
        bounded(value)
        if not isinstance(value, dict) or set(value) - ({"proxies", "proxy-groups"} if args.format == "Clash" else {"outbounds"}):
            raise ValueError("fragment")
        if args.format == "Clash":
            yaml = YAML(); yaml.default_flow_style = False; yaml.allow_unicode = True
            stream = io.StringIO(); yaml.dump(value, stream); output = stream.getvalue()
        else:
            output = json.dumps(value, ensure_ascii=False, indent=2) + "\n"
        if len(output.encode("utf-8")) > 1024 * 1024:
            raise ValueError("size")
    sys.stdout.buffer.write(output.encode("utf-8"))


if __name__ == "__main__":
    try:
        main()
    except Exception:
        # Parser exception text can include connection credentials and is never
        # an acceptable error response from this read-only UI helper.
        sys.stderr.write("ClientOutputReviewFailed\n")
        sys.exit(1)
