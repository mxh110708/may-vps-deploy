"""Choose CI work from a complete Git diff; ambiguous input requests full validation."""
import argparse
import json
import os
from pathlib import Path, PurePosixPath
import re
import subprocess
import urllib.error
import urllib.parse
import urllib.request


ROOT = Path(__file__).resolve().parents[2]
GROUPS = ("foundation", "clients", "xhttp", "chains", "quic", "udp",
          "server-stream", "operations", "outbound")
RECEIPT = "Full validation receipt"
SHARDS = {
    "clients-quic": ("clients", "quic"),
    "foundation-forwarding": ("foundation", "chains", "operations"),
    "streams-udp": ("xhttp", "udp", "server-stream", "outbound"),
}
RUNTIME_BOUNDARIES = [{"python": "3.9", "powershell": "7.4.20"},
                      {"python": "3.13", "powershell": "runner"}]


def test_groups(name):
    """A protocol fixture edit does not justify replaying unrelated protocols."""
    if name in ("Program.cs", "ProcessIdentityTests.cs"):
        return {"foundation"}
    if name in ("PrivateDirectoryTests.cs", "SshConfirmationTests.cs"):
        return {"foundation", "operations"}
    families = (("Client", "RouteDiagnostic", "ServerOutbound", "ServerDestination", "ServerHop", "RealityOutbound"),
                ("Forward", "Chain", "SharedChain", "TcpChain", "TcpForward", "WireGuard"),
                ("Hysteria", "Tuic"), ("Udp", "ApplicationUdp", "ServerQuic"),
                ("ServerStream", "ServerXhttp"))
    for prefixes, groups in zip(families, ({"clients"}, {"chains"}, {"quic"}, {"udp"}, {"server-stream"})):
        if name.startswith(prefixes):
            return groups
    if name.startswith("Xhttp"):
        return {"xhttp", "server-stream"}
    if name.startswith("Inbound"):
        return {"chains", "udp", "server-stream"}
    if name.startswith("OutboundAddress"):
        return {"outbound"}
    return set(GROUPS)


def matrix(items):
    return {"include": items}


def classify(paths, full=False, reason=None):
    groups, reasons = set(), []
    legacy = remote = shell = desktop = installer = linux = macos = False
    full = bool(full)
    if reason:
        reasons.append(reason)
    for path in paths:
        # Git uses forward slashes. Reject malformed/unbounded paths rather than guessing.
        if (not isinstance(path, str) or not path or "\\" in path or "\n" in path
                or PurePosixPath(path).is_absolute() or ".." in PurePosixPath(path).parts):
            full = True
            reasons.append("Invalid changed path")
            continue
        name = PurePosixPath(path).name
        if name == "AGENTS.md":
            continue
        elif ((path.startswith("docs/") and path.endswith(".md"))
              or ("/" not in path and path.endswith(".md"))):
            continue
        elif path.startswith((".github/", "scripts/ci/")) or path in ("tests/test_ci45.py", "scripts/Test-NoSecrets.ps1"):
            if path.startswith(".github/") or name == "run.py":
                groups.add("foundation")
                linux = macos = True
            if name == "contracts.json":
                remote = True
            if name == "Initialize-ClientCores.ps1":
                legacy = True
        elif (path.startswith(("vendor/", "assets/kernel/"))
              or name in ("Directory.Build.props", "global.json", "packages.lock.json")
              or path.startswith("requirements-") or path in (".gitignore", ".gitattributes")
              or name.endswith(".csproj") or path.startswith("config/")):
            full = True
        elif path.startswith("desktop/May.VpsDeploy.Desktop/"):
            desktop = True
            groups.add("foundation")
        elif path.startswith("desktop/May.VpsDeploy.Windows/"):
            desktop = True
            groups.update(("foundation", "operations"))
            if "Update" in name or "Private" in name or "Services" in name:
                installer = True
        elif path.startswith("desktop/May.VpsDeploy.Windows.Tests/"):
            groups.add("foundation")
        elif path.startswith(("desktop/May.VpsDeploy.Core/", "desktop/May.VpsDeploy.Infrastructure/")):
            # These layers cross protocol, archive and recovery boundaries. Run every core
            # group, but don't repeat the minimum-runtime/installer matrix for an ordinary fix.
            groups.update(GROUPS)
            desktop = True
            remote = True
            linux = macos = True
        elif path.startswith("desktop/May.VpsDeploy.Tests/"):
            groups.update(test_groups(name))
            if name in ("Program.cs", "Fixtures.cs", "ProcessIdentityTests.cs", "TestProcessIdentity.cs", "PrivateDirectoryTests.cs", "SshConfirmationTests.cs"):
                linux = macos = True
        elif path.startswith("assets/remote/"):
            remote = shell = True
            groups.update(("foundation", "operations"))
        elif path.startswith(("assets/installer/", "src/desktop/")):
            installer = legacy = True
            groups.add("foundation")
        elif path.startswith("assets/gui/"):
            desktop = True
        elif path.startswith(("src/", "modules/")) or name.startswith("Start-VPSDeploy"):
            legacy = remote = True
            if "Update" in name:
                installer = True
        elif path.startswith("templates/client/"):
            legacy = True
            remote = True
            groups.update(("foundation", "clients", "xhttp", "server-stream", "outbound"))
        elif path.startswith("scripts/"):
            if name.startswith(("New-VpsRelease", "Initialize-Desktop", "Test-Desktop")):
                installer = True
            else:
                # Shared renderers/bootstrap helpers are consumed by both implementations.
                legacy = remote = True
                groups.update(GROUPS)
        elif path.startswith("tests/"):
            if name == "Run-Tests.ps1":
                legacy = True
            elif "DesktopInstaller" in name or "BackgroundNative" in name:
                installer = True
            elif name.endswith(".ps1"):
                legacy = True
            elif name.endswith(".py"):
                remote = True
                groups.update(GROUPS)
            else:
                full = True
        else:
            full = True
            reasons.append("Unclassified path: " + path)
    if full:
        groups.update(GROUPS)
        legacy = remote = shell = installer = linux = macos = True
        reasons.append("Full validation")
    # Packaging already compiles the actual WinUI consumer. A second standalone
    # compilation in the same plan adds no coverage.
    if installer:
        desktop = False
    if groups:
        groups.add("foundation")
    selected = [g for g in GROUPS if g in groups]
    windows = [{"shard": name, "groups": [g for g in members if g in groups]}
               for name, members in SHARDS.items() if any(g in groups for g in members)]
    compatibility = [dict(r) for r in (RUNTIME_BOUNDARIES if full else RUNTIME_BOUNDARIES[-1:])]
    return {
        "schema": 1, "full": full, "reuse_run_id": "", "changed_paths": len(paths),
        "reasons": reasons or ["Changed-file selection" if paths else "No content changes"],
        "core": bool(selected), "core_groups": selected, "windows_matrix": matrix(windows),
        "linux": linux, "macos": macos, "legacy": legacy, "powershell_matrix": matrix(compatibility),
        "contracts": remote, "debian_matrix": matrix([{"debian": v} for v in ("12", "13")]),
        "shell": shell, "desktop": desktop, "installer": installer,
    }


def git(root, *args):
    return subprocess.run(["git", "-c", "safe.directory=" + str(root), *args],
                          cwd=root, check=True, stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE, timeout=30).stdout


def changed_paths(root, base, head):
    for sha in (base, head):
        if not isinstance(sha, str) or not re.fullmatch(r"[0-9a-fA-F]{40}", sha) or set(sha) == {"0"}:
            raise ValueError("Missing diff commit")
        try:
            git(root, "cat-file", "-e", sha + "^{commit}")
        except subprocess.CalledProcessError:
            git(root, "fetch", "--no-tags", "--depth=1", "origin", sha)
    # No API file limit, and no rename heuristic: both the deleted and added path are seen.
    raw = git(root, "diff", "--name-only", "--no-renames", "-z", base, head, "--")
    return [s.decode("utf-8", errors="strict") for s in raw.split(b"\0") if s]


def request_json(path):
    headers = {"Accept": "application/vnd.github+json", "User-Agent": "may-deploy-ci",
               "X-GitHub-Api-Version": "2022-11-28"}
    token = os.environ.get("GH_TOKEN", "")
    if token:
        headers["Authorization"] = "Bearer " + token
    request = urllib.request.Request("https://api.github.com" + path, headers=headers)
    with urllib.request.urlopen(request, timeout=15) as response:
        return json.load(response)


def reusable_full_run(repository, sha, current_run, fetch=request_json):
    if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repository):
        return ""
    query = urllib.parse.urlencode({"head_sha": sha, "status": "success", "per_page": 30})
    prefix = "/repos/" + repository + "/actions"
    runs = fetch(prefix + "/workflows/ci.yml/runs?" + query).get("workflow_runs", [])
    checked = 0
    for run in runs:
        if (str(run.get("id")) == str(current_run) or run.get("head_sha") != sha
                or run.get("conclusion") != "success" or run.get("status") != "completed"
                or run.get("path") != ".github/workflows/ci.yml"
                or run.get("event") not in ("push", "workflow_dispatch")
                or run.get("head_branch") != "main"):
            continue
        # Keep metadata lookup inside the selector job's own deadline. No qualifying
        # receipt in the bounded search simply requests a new complete validation.
        if checked == 5:
            break
        checked += 1
        jobs = fetch(prefix + "/runs/" + str(int(run["id"])) + "/jobs?per_page=100").get("jobs", [])
        if any(j.get("name") == RECEIPT and j.get("conclusion") == "success" for j in jobs):
            return str(int(run["id"]))
    return ""


def event_plan(root, event, event_name, ref, head, full=False, fetch=request_json):
    if ref.startswith("refs/tags/"):
        try:
            reused = reusable_full_run(os.environ.get("GITHUB_REPOSITORY", ""), head,
                                       os.environ.get("GITHUB_RUN_ID", ""), fetch)
        except (OSError, ValueError, KeyError, TypeError, urllib.error.URLError):
            reused = ""
        if reused:
            result = classify([], reason="Reuse trusted full validation for identical commit")
            result["reuse_run_id"] = reused
            return result
        return classify([], True, "Tag has no reusable full validation")
    if event_name == "workflow_dispatch":
        return classify([], True, "Explicit full validation")
    if full:
        return classify([], True, "Explicit full validation")
    try:
        if event_name == "pull_request":
            base, diff_head = event["pull_request"]["base"]["sha"], event["pull_request"]["head"]["sha"]
        elif event_name == "push":
            base, diff_head = event["before"], head
        else:
            return classify([], True, "Unknown event")
        return classify(changed_paths(root, base, diff_head))
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError):
        return classify([], True, "Diff unavailable; complete validation required")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument("--files-json", type=Path)
    parser.add_argument("--full", action="store_true")
    parser.add_argument("--output", type=Path, default=ROOT / ".tmp/ci/plan.json")
    args = parser.parse_args()
    if args.files_json:
        paths = json.loads(args.files_json.read_text(encoding="utf-8-sig"))
        if not isinstance(paths, list):
            raise ValueError("Changed files must be an array")
        plan = classify(paths, args.full)
    else:
        try:
            event = json.loads(Path(os.environ["GITHUB_EVENT_PATH"]).read_text(encoding="utf-8"))
        except (OSError, ValueError, KeyError):
            event = {}
        head = git(args.root, "rev-parse", "HEAD").decode().strip()
        plan = event_plan(args.root, event, os.environ.get("GITHUB_EVENT_NAME", ""),
                          os.environ.get("GITHUB_REF", ""), head, args.full)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(plan, indent=2) + "\n", encoding="utf-8")
    if os.environ.get("GITHUB_OUTPUT"):
        with open(os.environ["GITHUB_OUTPUT"], "a", encoding="utf-8") as output:
            for key, value in plan.items():
                if isinstance(value, (bool, list, dict)):
                    value = json.dumps(value, separators=(",", ":"))
                output.write(key + "=" + str(value) + "\n")
    print(json.dumps(plan, indent=2))


if __name__ == "__main__":
    main()
