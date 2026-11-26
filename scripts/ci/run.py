"""Run one owned CI suite with per-command deadlines and machine-readable timings."""
import argparse
import json
import os
from pathlib import Path
import platform
import shutil
import signal
import subprocess
import sys
import time

from plan import GROUPS

ROOT = Path(__file__).resolve().parents[2]
TEST_PROJECT = "desktop/May.VpsDeploy.Tests/May.VpsDeploy.Tests.csproj"
TEST_DLL = "desktop/May.VpsDeploy.Tests/bin/Release/net10.0/May.VpsDeploy.Tests.dll"


def selected_groups(value):
    groups = json.loads(value)
    if (not isinstance(groups, list) or not groups or len(groups) != len(set(groups))
            or any(g not in GROUPS for g in groups)):
        raise ValueError("Expected distinct known .NET test groups")
    return groups


def runtime_environment(root, system=None):
    env = dict(os.environ)
    env["MAY_TEST_SSH_PYTHON"] = sys.executable
    # Optional native builders load Windows executables. Unix shared-model jobs
    # must not enter those branches merely because Python itself is installed.
    if (system or platform.system()) == "Windows":
        env["MAY_TEST_PYTHON"] = sys.executable
        env["MAY_TEST_XRAY"] = str(root / ".cache/ci-xray/26.3.27/core/xray.exe")
    else:
        env.pop("MAY_TEST_PYTHON", None)
        env.pop("MAY_TEST_XRAY", None)
    return env


def steps_for(suite, root, groups=None):
    pwsh = "pwsh"
    if suite == "quick":
        return [("CI behavior regressions", [sys.executable, "tests/test_ci45.py"], 90),
                ("Documentation links", [sys.executable, "scripts/ci/check_docs.py"], 90),
                ("PowerShell syntax and secrets", [pwsh, "-NoProfile", "-File",
                 "scripts/ci/Test-Quick.ps1", "-ProjectRoot", str(root)], 120)]
    if suite == "contracts":
        entries = json.loads((root / "scripts/ci/contracts.json").read_text(encoding="utf-8"))
        bash = shutil.which("bash")
        if not bash:
            raise RuntimeError("Contract tests require Bash")
        result = []
        for entry in entries:
            if not (root / entry["path"]).is_file():
                raise RuntimeError("Missing catalogued contract: " + entry["path"])
            command = [sys.executable, entry["path"]]
            if entry.get("bash"):
                command += ["--bash", bash]
            result.append((entry["path"], command, 120))
        return result
    if suite == "legacy":
        return [("PowerShell and CLI behavior", [pwsh, "-NoProfile", "-STA", "-File",
                 "tests/Run-Tests.ps1", "-ProjectRoot", str(root), "-SkipPortableRegressions"], 300),
                ("Fixed client cores and configurations", [pwsh, "-NoProfile", "-File",
                 "scripts/ci/Initialize-ClientCores.ps1", "-ProjectRoot", str(root), "-CheckConfigs"], 180)]
    if suite == "desktop":
        project = "desktop/May.VpsDeploy.Desktop/May.VpsDeploy.Desktop.csproj"
        return [("WinUI locked restore", ["dotnet", "restore", project, "--locked-mode", "-p:Platform=x64"], 180),
                ("WinUI compile", ["dotnet", "build", project, "-c", "Release", "--no-restore", "-p:Platform=x64", "-m:1", "-nr:false"], 180)]
    if suite == "installer":
        return [("Isolated install, upgrade and uninstall", [pwsh, "-NoProfile", "-STA", "-File",
                 "tests/Test-DesktopInstaller.ps1", "-ProjectRoot", str(root)], 900)]
    if suite in ("dotnet", "platform"):
        if suite == "dotnet" and not groups:
            raise ValueError(".NET suite requires explicit groups")
        result = [("Locked .NET restore", ["dotnet", "restore", TEST_PROJECT, "--locked-mode"], 180),
                  (".NET test build", ["dotnet", "build", TEST_PROJECT, "-c", "Release", "--no-restore"], 180)]
        if suite == "platform":
            return result + [("Platform filesystem, process and SSH contracts",
                              ["dotnet", TEST_DLL, str(root), "--platform-only"], 120)]
        if platform.system() == "Windows" and any(g != "foundation" for g in groups):
            result.append(("Verified fixed client cores", [pwsh, "-NoProfile", "-File",
                           "scripts/ci/Initialize-ClientCores.ps1", "-ProjectRoot", str(root), "-Xray"], 180))
        for group in groups:
            if group == "server-stream":
                result += [("Stream next hops", ["dotnet", TEST_DLL, str(root), "--server-stream-only"], 480),
                           ("XHTTP next hops", ["dotnet", TEST_DLL, str(root), "--server-xhttp-only"], 480)]
            elif group == "outbound":
                result.append(("Address-family boundaries", ["dotnet", TEST_DLL, str(root), "--outbound-address-only"], 120))
                if platform.system() == "Windows":
                    result.append(("Address-family actual fixed-core paths", [pwsh, "-NoProfile", "-File",
                                   "scripts/ci/Initialize-ClientCores.ps1", "-ProjectRoot", str(root), "-AddressRuntime"], 180))
            else:
                result.append((".NET " + group, ["dotnet", TEST_DLL, str(root), "--group", group], 480 if group == "chains" else 360))
        if platform.system() == "Windows" and "foundation" in groups:
            project = "desktop/May.VpsDeploy.Windows.Tests/May.VpsDeploy.Windows.Tests.csproj"
            result += [("Windows adapters locked restore", ["dotnet", "restore", project, "--locked-mode"], 180),
                       ("Windows adapters and credentials", ["dotnet", "run", "--project", project,
                        "-c", "Release", "--no-restore", "--", str(root)], 180)]
        return result
    raise ValueError("Unknown suite")


def stop_owned(process):
    if process.poll() is not None:
        return
    if os.name == "nt":
        try:
            subprocess.run(["taskkill", "/PID", str(process.pid), "/T", "/F"],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=5, check=False)
        except (OSError, subprocess.TimeoutExpired):
            pass
        # A restricted local test host can deny taskkill's process enumeration even
        # while the handle returned by Popen still permits stopping our own child.
        if process.poll() is None:
            process.kill()
    else:
        os.killpg(process.pid, signal.SIGKILL)
    process.wait(timeout=15)


def run_steps(steps, root, report, env=None):
    results = []
    report.parent.mkdir(parents=True, exist_ok=True)
    def save(status):
        report.write_text(json.dumps({"status": status, "steps": results,
                                     "seconds": round(sum(r["seconds"] for r in results), 3)},
                                    indent=2) + "\n", encoding="utf-8")
    save("running")
    complete = False
    try:
        for name, command, timeout in steps:
            print("::group::" + name, flush=True)
            started = time.monotonic()
            process = None
            result = {"name": name, "deadline_seconds": timeout, "status": "failed"}
            try:
                process = subprocess.Popen(command, cwd=root, env=env,
                                           start_new_session=(os.name != "nt"))
                result["exit_code"] = process.wait(timeout=timeout)
                result["status"] = "passed" if result["exit_code"] == 0 else "failed"
            except subprocess.TimeoutExpired:
                result["status"] = "timeout"
                raise
            except KeyboardInterrupt:
                result["status"] = "cancelled"
                raise
            finally:
                try:
                    if process is not None:
                        stop_owned(process)
                finally:
                    result["seconds"] = round(time.monotonic() - started, 3)
                    results.append(result)
                    save("running")
                    print("::endgroup::", flush=True)
            if result["status"] != "passed":
                raise RuntimeError("CI step failed: " + name)
        complete = True
    finally:
        save("passed" if complete else "failed")
        summary = os.environ.get("GITHUB_STEP_SUMMARY")
        if summary:
            with open(summary, "a", encoding="utf-8") as output:
                output.write("\n| Check | Result | Execution seconds |\n| --- | --- | ---: |\n")
                for row in results:
                    output.write("| {name} | {status} | {seconds} |\n".format(**row))
    return results


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--suite", choices=("quick", "contracts", "legacy", "dotnet", "platform", "desktop", "installer"), required=True)
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument("--groups", default=os.environ.get("MAY_CI_GROUPS", "[]"))
    parser.add_argument("--report", type=Path)
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()
    groups = selected_groups(args.groups) if args.suite == "dotnet" else None
    steps = steps_for(args.suite, args.root, groups)
    if args.dry_run:
        print(json.dumps(steps, indent=2))
        return
    env = runtime_environment(args.root)
    # GitHub cancellation must also stop the runner's own subprocess tree.
    def cancelled(signum, frame):
        raise KeyboardInterrupt("CI cancelled")
    signal.signal(signal.SIGTERM, cancelled)
    run_steps(steps, args.root, args.report or args.root / (".tmp/ci/" + args.suite + ".json"), env)


if __name__ == "__main__":
    main()
