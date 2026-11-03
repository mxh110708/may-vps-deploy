"""Read-only difference/fragment behavior; no client or network processes."""
import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[1] / "scripts/client_output_review.py"
spec = importlib.util.spec_from_file_location("client_output_review", SCRIPT)
review = importlib.util.module_from_spec(spec)
spec.loader.exec_module(review)


def temporary():
    # macOS commonly exposes /var through a system symlink. Resolve the trusted
    # temporary root, then keep testing rejection of links inside the fixture.
    return tempfile.TemporaryDirectory(dir=Path(tempfile.gettempdir()).resolve())


class OutputReview(unittest.TestCase):
    def test_safe_diff_counts(self):
        before = {"proxies": [{"name": "A", "password": "PRIVATE-OLD"}, {"name": "B"}], "proxy-groups": [{"name": "G", "proxies": ["A"]}], "dns": {"enable": True}, "rules": ["MATCH,G"]}
        after = {"proxies": [{"name": "A", "password": "PRIVATE-NEW"}, {"name": "C"}], "proxy-groups": [{"name": "G", "proxies": ["C"]}], "dns": {"enable": False}, "rules": ["MATCH,DIRECT"]}
        result = review.review(before, after, "Clash")
        self.assertEqual(result["Nodes"], {"Added": 1, "Removed": 1, "Changed": 1})
        self.assertEqual(result["Groups"]["Changed"], 1)
        self.assertTrue(result["RulesChanged"] and result["DnsChanged"])
        self.assertNotIn("PRIVATE", json.dumps(result))
        self.assertNotIn("password", json.dumps(result))

    def test_sing_selector_and_global_changes(self):
        a = {"outbounds": [{"tag": "A", "type": "anytls", "password": "x"}, {"tag": "G", "type": "selector", "outbounds": ["A"]}]}
        b = json.loads(json.dumps(a)); b["outbounds"][1]["outbounds"] = ["DIRECT"]; b["log"] = {"level": "warn"}; b["inbounds"] = [{"type": "mixed"}]
        result = review.review(a, b, "SingBox")
        self.assertEqual(result["Nodes"], {"Added": 0, "Removed": 0, "Changed": 0})
        self.assertEqual(result["Groups"]["Changed"], 1)
        self.assertTrue(result["SettingsChanged"] and result["ListenersChanged"])

    def test_duplicate_cycle_depth_and_type(self):
        with temporary() as root:
            path = Path(root) / "test.yaml"
            for text in ("proxies: []\nproxies: []\n", "a: &a [*a]\n", "? [x,y]\n: z\n", "a: !!timestamp 2026-01-01\n"):
                path.write_text(text, encoding="utf-8")
                with self.assertRaises(Exception):
                    review.load(path, "Clash")
            path = Path(root) / "test.json"
            for text in ('{"a":1,"a":2}', '{"a":NaN}', '{"a":' + "[" * 66 + "0" + "]" * 66 + "}"):
                path.write_text(text, encoding="utf-8")
                with self.assertRaises(Exception):
                    review.load(path, "SingBox")

    def test_read_only_hash_missing_and_link(self):
        with temporary() as root:
            path = Path(root) / "nodes.json"; text = '{"outbounds":[]}'; path.write_text(text, encoding="utf-8")
            obj, digest = review.load(path, "SingBox")
            self.assertEqual(digest, review.hashlib.sha256(text.encode()).hexdigest())
            self.assertEqual(review.load(Path(root) / "absent.json", "SingBox", True), ({}, "missing"))
            self.assertEqual(path.read_text(encoding="utf-8"), text)
            link = Path(root) / "link.json"
            try:
                link.symlink_to(path)
            except OSError:
                return
            with self.assertRaises(ValueError):
                review.load(link, "SingBox")

    def test_native_serialization_and_safe_parser_error(self):
        content = {"proxies": [{"name": "花 / : #", "type": "anytls", "password": "a:#雪\ntrue", "ech-opts": {"enable": True, "config": "opaque=="}}]}
        result = subprocess.run([sys.executable, str(SCRIPT), "fragment", "--format", "Clash"], input=json.dumps(content).encode(), capture_output=True, timeout=10)
        self.assertEqual(result.returncode, 0)
        self.assertEqual(review.YAML(typ="safe").load(result.stdout.decode("utf-8")), content)
        with temporary() as root:
            bad = Path(root) / "bad.yaml"; bad.write_text("password: [PRIVATE-SECRET", encoding="utf-8")
            result = subprocess.run([sys.executable, str(SCRIPT), "review", "--format", "Clash", "--before", str(bad), "--after", str(bad)], capture_output=True, timeout=10)
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(result.stderr.decode().strip(), "ClientOutputReviewFailed")
            self.assertNotIn(b"PRIVATE", result.stdout + result.stderr)

    def test_bounded_alias_and_oversize(self):
        leaf = ["x"]
        for _ in range(18):
            leaf = [leaf, leaf]
        with self.assertRaises(ValueError):
            review.bounded(leaf)
        with temporary() as root:
            path = Path(root) / "large.json"; path.write_bytes(b" " * (review.LIMIT + 1))
            with self.assertRaises(ValueError):
                review.load(path, "SingBox")


if __name__ == "__main__":
    unittest.main()
