"""Enforce the selected CI checks and report GitHub queue/execution timings."""
import argparse
from datetime import datetime
import json
import os
from pathlib import Path
import re

from plan import GROUPS, RUNTIME_BOUNDARIES, request_json

REQUIRED = {"contracts": "contracts", "legacy": "legacy", "core": "core",
            "desktop": "desktop", "installer": "installer", "shell": "shell"}


def check_gate(needs):
    if not isinstance(needs, dict) or needs.get("plan", {}).get("result") != "success":
        raise ValueError("CI selection did not succeed")
    outputs = needs["plan"].get("outputs", {})
    if outputs.get("full") not in ("true", "false"):
        raise ValueError("Missing full-validation selection")
    if outputs["full"] == "true" and any(outputs.get(flag) != "true" for flag in REQUIRED.values() if flag != "desktop"):
        raise ValueError("Full validation must select every suite")
    if outputs.get("desktop") == "true" and outputs.get("installer") == "true":
        raise ValueError("Installer compilation must not be duplicated by the desktop job")
    if any(outputs.get(flag) not in ("true", "false") for flag in ("linux", "macos")):
        raise ValueError("Missing platform compatibility selection")
    for platform in ("linux", "macos"):
        if outputs[platform] == "true" and needs.get("core", {}).get("outputs", {}).get(platform + "_result") != "success":
            raise ValueError("Selected platform compatibility check did not succeed: " + platform)
    if outputs.get("core") == "true":
        groups = json.loads(outputs.get("core_groups", "[]"))
        windows = json.loads(outputs.get("windows_matrix", "{}"))
        assigned = [g for row in windows.get("include", []) for g in row.get("groups", [])]
        if (not groups or any(g not in GROUPS for g in groups) or len(groups) != len(set(groups))
                or len(assigned) != len(set(assigned)) or set(assigned) != set(groups)):
            raise ValueError("Core groups are missing or duplicated in the Windows matrix")
    if outputs["full"] == "true":
        compatibility = json.loads(outputs.get("powershell_matrix", "{}")).get("include", [])
        combinations = {(row.get("python"), row.get("powershell")) for row in compatibility}
        debian = json.loads(outputs.get("debian_matrix", "{}")).get("include", [])
        if (set(groups) != set(GROUPS) or outputs.get("macos") != "true" or outputs.get("linux") != "true"
                or len(compatibility) != 2
                or combinations != {(r["python"], r["powershell"]) for r in RUNTIME_BOUNDARIES}
                or len(debian) != 2 or {row.get("debian") for row in debian} != {"12", "13"}):
            raise ValueError("Full platform or runtime compatibility matrix is incomplete")
    for job, flag in REQUIRED.items():
        selected = outputs.get(flag)
        if selected not in ("true", "false"):
            raise ValueError("Missing selection for " + job)
        status = needs.get(job, {}).get("result")
        if status not in (("success",) if selected == "true" else ("success", "skipped")):
            raise ValueError("Required check did not succeed: " + job)
    if needs.get("quick", {}).get("result") != "success":
        raise ValueError("Quick checks did not succeed")
    if any(v.get("result") not in ("success", "skipped") for v in needs.values()):
        raise ValueError("A CI dependency failed or was cancelled")


def seconds(start, end):
    if not start or not end:
        return None
    return max(0, round((datetime.fromisoformat(end.replace("Z", "+00:00"))
                         - datetime.fromisoformat(start.replace("Z", "+00:00"))).total_seconds(), 3))


def timing_rows(run, jobs):
    return [{"name": j["name"], "result": j.get("conclusion") or j.get("status"),
             "queue_seconds": seconds(j.get("created_at") or run["created_at"], j.get("started_at")),
             "execution_seconds": seconds(j.get("started_at"), j.get("completed_at"))}
            for j in jobs]


def timings():
    repository, run_id = os.environ.get("GITHUB_REPOSITORY", ""), os.environ.get("GITHUB_RUN_ID", "")
    if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repository) or not run_id.isdigit():
        raise ValueError("Missing workflow identity")
    prefix = "/repos/" + repository + "/actions/runs/" + run_id
    run = request_json(prefix)
    jobs = []
    for page in range(1, 11):
        batch = request_json(prefix + "/jobs?per_page=100&page=" + str(page)).get("jobs", [])
        jobs.extend(batch)
        if len(batch) < 100:
            break
    rows = timing_rows(run, jobs)
    path = Path(".tmp/ci/workflow-timing.json")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({"run_id": run_id, "jobs": rows}, indent=2) + "\n", encoding="utf-8")
    text = "\n| Job | Result | Queue seconds | Execution seconds |\n| --- | --- | ---: | ---: |\n"
    for row in rows:
        text += "| {name} | {result} | {queue_seconds} | {execution_seconds} |\n".format(**row)
    print(text)
    if os.environ.get("GITHUB_STEP_SUMMARY"):
        with open(os.environ["GITHUB_STEP_SUMMARY"], "a", encoding="utf-8") as output:
            output.write(text)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--gate", action="store_true")
    parser.add_argument("--timings", action="store_true")
    args = parser.parse_args()
    if args.gate:
        check_gate(json.loads(os.environ["MAY_CI_NEEDS"]))
        print("Every selected check succeeded")
    if args.timings:
        try:
            timings()
        except (OSError, ValueError, KeyError, TypeError):
            # Diagnostic availability cannot erase the independent gate's result.
            print("::warning::GitHub timing data unavailable; per-suite timing artifacts remain available")
