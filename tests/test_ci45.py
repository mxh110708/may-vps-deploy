"""Behavior checks for CI selection, fail-closed gates, receipts and deadlines."""
import copy
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
TEMP_ROOT = ROOT / ".tmp/ci45-unit"
TEMP_ROOT.mkdir(parents=True, exist_ok=True)
sys.path.insert(0, str(ROOT / "scripts/ci"))
import plan
import result
import run
import check_docs


def needs_for(selection):
    needs = {"plan": {"result": "success", "outputs": {
        k: json.dumps(v, separators=(",", ":")) if isinstance(v, (list, dict, bool)) else str(v)
        for k, v in selection.items()}}, "quick": {"result": "success"}}
    needs.update({j: {"result": "success" if selection[f] else "skipped"}
                  for j, f in result.REQUIRED.items()})
    return needs


class Selection(unittest.TestCase):
    def test_documentation_has_only_fast_checks(self):
        p = plan.classify(["README.md", "docs/MAINTENANCE.zh-CN.md", "CHANGELOG.md"])
        self.assertFalse(any(p[k] for k in result.REQUIRED.values()))
        self.assertFalse(p["full"])
        result.check_gate(needs_for(p))

    def test_ui_does_not_run_installer_or_protocol_matrix(self):
        p = plan.classify(["desktop/May.VpsDeploy.Desktop/MainWindow.xaml.cs"])
        self.assertTrue(p["desktop"])
        self.assertFalse(p["installer"])
        self.assertEqual(p["core_groups"], ["foundation"])
        self.assertFalse(p["macos"])

    def test_shared_core_keeps_every_core_group(self):
        p = plan.classify(["desktop/May.VpsDeploy.Core/Storage.cs"])
        self.assertEqual(p["core_groups"], list(plan.GROUPS))
        self.assertTrue(p["contracts"])
        self.assertTrue(p["desktop"])
        self.assertFalse(p["installer"])
        self.assertFalse(p["macos"])

    def test_installer_and_update_changes_select_lifecycle(self):
        for path in ("assets/installer/Desktop.iss", "src/VpsDeploy.Update.psm1",
                     "desktop/May.VpsDeploy.Windows/WindowsUpdates.cs", "scripts/New-VpsReleasePackage.ps1"):
            with self.subTest(path=path):
                self.assertTrue(plan.classify([path])["installer"])
        self.assertTrue(plan.classify(["desktop/May.VpsDeploy.Windows/WindowsWindowPlacement.cs"])["desktop"])

    def test_remote_scripts_keep_both_supported_debian_versions(self):
        p = plan.classify(["assets/remote/tcp-forward-apply.sh"])
        self.assertTrue(p["contracts"])
        self.assertTrue(p["shell"])
        self.assertEqual([r["debian"] for r in p["debian_matrix"]["include"]], ["12", "13"])

    def test_global_and_unknown_changes_request_full(self):
        for path in (".github/workflows/ci.yml", "scripts/ci/plan.py", "requirements-test.txt",
                     "desktop/global.json", "desktop/May.VpsDeploy.Core/packages.lock.json",
                     "config/versions.json", "AGENTS.md", "docs/AGENTS.md", "scripts/Test-NoSecrets.ps1", "new-unclassified-file", "desktop/new-project/a.cs"):
            with self.subTest(path=path):
                p = plan.classify([path])
                self.assertTrue(p["full"])
                self.assertTrue(p["installer"])
                self.assertEqual(len(p["powershell_matrix"]["include"]), 4)

    def test_invalid_paths_request_full(self):
        for path in ("../README.md", "/README.md", "docs\\README.md", "docs/a\nb.md", None):
            self.assertTrue(plan.classify([path])["full"])

    def test_group_shards_have_no_missing_or_duplicate_groups(self):
        for p in (plan.classify([], True), plan.classify(["templates/client/example.json"]),
                  plan.classify(["desktop/May.VpsDeploy.Desktop/MainWindow.xaml"])):
            groups = [g for shard in p["windows_matrix"]["include"] for g in shard["groups"]]
            self.assertEqual(len(groups), len(set(groups)))
            self.assertEqual(set(groups), set(p["core_groups"]))

    def test_missing_or_zero_diff_requests_full(self):
        for event in ({}, {"before": "0" * 40}, {"pull_request": {"base": {}}}):
            with mock.patch.object(plan, "changed_paths", side_effect=ValueError("missing")):
                self.assertTrue(plan.event_plan(ROOT, event, "push", "refs/heads/main", "a" * 40)["full"])

    def test_manual_validation_is_full_even_when_no_paths_changed(self):
        self.assertTrue(plan.event_plan(ROOT, {}, "workflow_dispatch", "refs/heads/main", "a" * 40)["full"])

    def test_missing_diff_object_is_fetched_without_shell_or_tag_fetch(self):
        calls = []
        def fake_git(root, *args):
            calls.append(args)
            if args[:3] == ("cat-file", "-e", "b" * 40 + "^{commit}"):
                raise subprocess.CalledProcessError(1, "git")
            return b"docs/a.md\0" if args[0] == "diff" else b""
        with mock.patch.object(plan, "git", side_effect=fake_git):
            self.assertEqual(plan.changed_paths(ROOT, "b" * 40, "a" * 40), ["docs/a.md"])
        self.assertIn(("fetch", "--no-tags", "--depth=1", "origin", "b" * 40), calls)

    def test_complete_git_diff_handles_renames_deletions_and_over_300_files(self):
        with tempfile.TemporaryDirectory(dir=TEMP_ROOT) as temporary:
            root = Path(temporary)
            def git(*args):
                child = subprocess.run(["git", "-c", "safe.directory=" + str(root),
                    "-c", "user.name=CI Fixture", "-c", "user.email=ci@example.invalid", *args],
                    cwd=root, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
                if child.returncode:
                    raise RuntimeError(child.stderr.decode("utf-8", errors="replace"))
                return child.stdout
            git("init", "-q")
            (root / "source.cs").write_text("old")
            git("add", "."); git("commit", "-qm", "baseline")
            before = git("rev-parse", "HEAD").decode().strip()
            (root / "source.cs").rename(root / "renamed.md")
            for number in range(320):
                (root / ("file-" + str(number) + ".md")).write_text("fixture")
            git("add", "-A"); git("commit", "-qm", "changes")
            head = git("rev-parse", "HEAD").decode().strip()
            paths = plan.changed_paths(root, before, head)
            self.assertEqual(len(paths), 322)
            self.assertIn("source.cs", paths)
            self.assertIn("renamed.md", paths)
            self.assertTrue(plan.classify(paths)["full"])


class Receipts(unittest.TestCase):
    def fixture(self, **overrides):
        row = {"id": 7, "head_sha": "a" * 40, "conclusion": "success", "status": "completed",
               "path": ".github/workflows/ci.yml", "event": "push", "head_branch": "main"}
        row.update(overrides)
        return row

    def fetch(self, row, receipt="success"):
        return lambda path: ({"workflow_runs": [row]} if "/workflows/" in path else
                             {"jobs": [{"name": plan.RECEIPT, "conclusion": receipt}]})

    def test_only_same_commit_trusted_complete_full_run_can_be_reused(self):
        fetch = self.fetch(self.fixture())
        self.assertEqual(plan.reusable_full_run("owner/repo", "a" * 40, "8", fetch), "7")
        for change in ({"head_sha": "b" * 40}, {"event": "pull_request"}, {"head_branch": "feature"},
                       {"conclusion": "cancelled"}, {"status": "in_progress"}, {"path": ".github/workflows/other.yml"}, {"id": 8}):
            with self.subTest(change=change):
                self.assertEqual(plan.reusable_full_run("owner/repo", "a" * 40, "8", self.fetch(self.fixture(**change))), "")

    def test_partial_skipped_or_failed_receipt_is_not_full_validation(self):
        for status in ("skipped", "failure", "cancelled", None):
            self.assertEqual(plan.reusable_full_run("owner/repo", "a" * 40, "8", self.fetch(self.fixture(), status)), "")

    def test_tag_reuses_full_run_and_does_not_issue_a_new_full_receipt(self):
        with mock.patch.object(plan.os, "environ", dict(os.environ, GITHUB_REPOSITORY="owner/repo", GITHUB_RUN_ID="8")):
            p = plan.event_plan(ROOT, {}, "push", "refs/tags/v0.9.43", "a" * 40, fetch=self.fetch(self.fixture()))
        self.assertEqual(p["reuse_run_id"], "7")
        self.assertFalse(p["full"])
        self.assertFalse(p["core"])

    def test_tag_api_failure_requests_full_instead_of_passing_unverified(self):
        def unavailable(path):
            raise OSError("unavailable")
        with mock.patch.object(plan.os, "environ", dict(os.environ, GITHUB_REPOSITORY="owner/repo")):
            self.assertTrue(plan.event_plan(ROOT, {}, "push", "refs/tags/v0.9.43", "a" * 40, fetch=unavailable)["full"])

    def test_receipt_search_has_a_bounded_request_budget(self):
        requested = []
        def fetch(path):
            requested.append(path)
            return {"workflow_runs": [self.fixture(id=n) for n in range(10)]} if "/workflows/" in path else {"jobs": []}
        self.assertEqual(plan.reusable_full_run("owner/repo", "a" * 40, "100", fetch), "")
        self.assertEqual(len(requested), 6)


class GatesAndRunner(unittest.TestCase):
    def test_selected_missing_skipped_failed_or_cancelled_check_fails(self):
        needs = needs_for(plan.classify([], True))
        result.check_gate(needs)
        for status in ("skipped", "failure", "cancelled", None):
            changed = copy.deepcopy(needs)
            changed["core"]["result"] = status
            with self.assertRaises(ValueError):
                result.check_gate(changed)

    def test_failed_plan_or_quick_checks_cannot_pass(self):
        for job in ("plan", "quick"):
            needs = needs_for(plan.classify(["README.md"]))
            needs[job]["result"] = "failure"
            with self.assertRaises(ValueError):
                result.check_gate(needs)

    def test_missing_selection_or_incomplete_full_plan_fails(self):
        needs = needs_for(plan.classify([], True))
        needs["plan"]["outputs"].pop("installer")
        with self.assertRaises(ValueError): result.check_gate(needs)
        needs["plan"]["outputs"]["installer"] = "false"
        with self.assertRaises(ValueError): result.check_gate(needs)

    def test_full_receipt_requires_all_platforms_versions_and_group_assignments(self):
        for key, value in (("macos", "false"), ("core_groups", '["foundation"]'),
                           ("windows_matrix", '{"include":[]}'),
                           ("powershell_matrix", '{"include":[{"python":"3.13","powershell":"runner"}]}'),
                           ("debian_matrix", '{"include":[{"debian":"13"}]}')):
            with self.subTest(key=key):
                needs = needs_for(plan.classify([], True))
                needs["plan"]["outputs"][key] = value
                with self.assertRaises(ValueError): result.check_gate(needs)

    def test_partial_core_plan_cannot_silently_drop_windows_groups(self):
        needs = needs_for(plan.classify(["desktop/May.VpsDeploy.Desktop/MainWindow.xaml.cs"]))
        needs["plan"]["outputs"]["windows_matrix"] = '{"include":[]}'
        with self.assertRaises(ValueError): result.check_gate(needs)

    def test_groups_reject_unknown_and_duplicate_names(self):
        for groups in ('[]', '["clients","clients"]', '["unknown"]', '"clients"'):
            with self.assertRaises(ValueError): run.selected_groups(groups)

    def test_unix_models_never_attempt_windows_native_executables(self):
        with mock.patch.object(run.os, "environ", {"MAY_TEST_PYTHON": "ambient", "MAY_TEST_XRAY": "ambient"}):
            for system in ("Linux", "Darwin"):
                env = run.runtime_environment(ROOT, system)
                self.assertNotIn("MAY_TEST_PYTHON", env)
                self.assertNotIn("MAY_TEST_XRAY", env)
                self.assertEqual(env["MAY_TEST_SSH_PYTHON"], sys.executable)
            env = run.runtime_environment(ROOT, "Windows")
            self.assertEqual(env["MAY_TEST_PYTHON"], sys.executable)
            self.assertTrue(env["MAY_TEST_XRAY"].endswith("xray.exe"))

    def test_chains_use_distinct_bounded_children_without_replaying_the_whole_group(self):
        steps = run.steps_for("dotnet", ROOT, ["chains"])
        phases = [(name, command, timeout) for name, command, timeout in steps if "--chain-phase" in command]
        self.assertEqual([command[-1] for name, command, timeout in phases],
                         ["forwarding-models", "adjacent-tunnels", "forwarding-paths",
                          "underlays", "shared-ipv4", "shared-ipv6", "shared-recovery", "wireguard-inbounds"])
        self.assertTrue(all(timeout == 240 for name, command, timeout in phases))
        self.assertFalse(any("--group" in command for name, command, timeout in steps))

    def test_stream_groups_keep_their_previous_deadlines(self):
        steps = run.steps_for("dotnet", ROOT, ["chains", "server-stream"])
        by_name = {name: timeout for name, command, timeout in steps}
        self.assertGreaterEqual(by_name["Stream next hops"], 480)
        self.assertGreaterEqual(by_name["XHTTP next hops"], 480)

    def test_failed_child_stops_following_work_and_records_failure(self):
        with tempfile.TemporaryDirectory(dir=TEMP_ROOT) as temporary:
            root = Path(temporary)
            steps = [("failure", [sys.executable, "-c", "raise SystemExit(3)"], 10),
                     ("must not run", [sys.executable, "-c", "open('unexpected','w').close()"], 10)]
            with self.assertRaises(RuntimeError): run.run_steps(steps, root, root / "report.json")
            self.assertFalse((root / "unexpected").exists())
            report = json.loads((root / "report.json").read_text())
            self.assertEqual(report["steps"][0]["exit_code"], 3)
            self.assertEqual(len(report["steps"]), 1)

    def test_timeout_is_failure_and_process_is_stopped(self):
        with tempfile.TemporaryDirectory(dir=TEMP_ROOT) as temporary:
            root = Path(temporary)
            children = []
            popen = run.subprocess.Popen
            def capture(*args, **kwargs):
                child = popen(*args, **kwargs)
                children.append(child)
                return child
            with mock.patch.object(run.subprocess, "Popen", side_effect=capture):
                with self.assertRaises(subprocess.TimeoutExpired):
                    run.run_steps([("timeout", [sys.executable, "-c", "import time; time.sleep(20)"], 0.05)], root, root / "report.json")
            self.assertEqual(json.loads((root / "report.json").read_text())["steps"][0]["status"], "timeout")
            self.assertTrue(all(child.poll() is not None for child in children))

    def test_launch_failure_replaces_stale_success_report(self):
        with tempfile.TemporaryDirectory(dir=TEMP_ROOT) as temporary:
            root = Path(temporary)
            report = root / "report.json"
            report.write_text('{"status":"passed"}')
            with self.assertRaises(FileNotFoundError):
                run.run_steps([("missing program", [str(root / "does-not-exist")], 1)], root, report)
            value = json.loads(report.read_text())
            self.assertEqual(value["status"], "failed")
            self.assertEqual(value["steps"][0]["name"], "missing program")

    def test_contract_manifest_is_unique_and_keeps_previous_drivers(self):
        catalog = json.loads((ROOT / "scripts/ci/contracts.json").read_text())
        paths = [e["path"] for e in catalog]
        self.assertEqual(len(paths), len(set(paths)))
        self.assertTrue(all((ROOT / p).is_file() for p in paths))
        # The original CLI still enumerates these drivers for non-CI complete validation.
        import re
        original = set(re.findall(r"tests[/\\](test_[A-Za-z0-9_]+\.py)", (ROOT / "tests/Run-Tests.ps1").read_text(encoding="utf-8-sig")))
        self.assertTrue({"tests/" + p for p in original if p != "test_ci45.py"}.issubset(paths))
        for path in ("tests/test_may_monitor_lifecycle.py", "tests/test_linux_core_upgrade.py", "tests/test_forward_proxy_health.py"):
            self.assertIn(path, paths)

    def test_queue_and_execution_timings_remain_distinct(self):
        rows = result.timing_rows({"created_at": "2026-11-25T09:17:11Z"}, [{"name": "fixture", "conclusion": "success",
            "started_at": "2026-11-25T09:30:07Z", "completed_at": "2026-11-25T09:47:16Z"}])
        self.assertEqual(rows[0]["queue_seconds"], 776)
        self.assertEqual(rows[0]["execution_seconds"], 1029)

    def test_document_links_check_real_targets_and_ignore_code_examples(self):
        with tempfile.TemporaryDirectory(dir=TEMP_ROOT) as temporary:
            root = Path(temporary); (root / "docs").mkdir()
            (root / "README.md").write_text('[exists](docs/ok.md)\n[missing](docs/missing.md)\n```\n[example](fiction.md)\n```\n', encoding="utf-8")
            (root / "docs/ok.md").write_text("ok")
            self.assertEqual(len(check_docs.broken_links(root)[1]), 1)


if __name__ == "__main__":
    unittest.main(verbosity=2)
