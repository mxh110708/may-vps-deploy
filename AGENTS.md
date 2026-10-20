# Repository Guidelines

## Project Structure & Module Organization

May VPS Deploy uses a WinUI 3 Windows desktop frontend and a cross-platform .NET operations core for Debian 12/13 amd64 targets. `desktop/` contains Core, Infrastructure, Windows adapters, Desktop and behavior tests. Core must not reference Windows APIs, WinUI, WPF or PowerShell. Infrastructure connects using SSH.NET; Windows adapters own DPAPI, key-copy ACLs and installer updates. `Start-VPSDeploy.ps1` and `src/` retain the mature legacy CLI. `assets/remote/` contains Bash operations; `scripts/` contains specialized Python configuration helpers. Public templates, pinned versions and client assets remain under `templates/client/`, `config/` and `vendor/test-cores/`.

The old WPF shell and bridge are historical source and regression references. The new desktop EXE never loads them; `Start-VPSDeploy.cmd` must not fall back to that driver. Desktop navigation uses forms, selected instances, client schemes and task outcomes; do not add CLI menu input or a legacy archive import UI.

`src/desktop/` retains small native update/guard helpers; `desktop/May.VpsDeploy.Desktop` builds the actual WinUI application. `assets/installer/` defines optional keep/remove-data uninstall. Bundle .NET, WinUI and the YAML helper runtime without changing global PATH or installing services. Preserve private/local files, reject managed edits, unmanaged collisions and links. A lost remote acknowledgement must trigger identity/status reconciliation, never an automatic mutation replay. Restore only the chosen component scope; reject unknown or legacy transactions before writing.

## Build, Test, and Development Commands

Use PowerShell 7.4+ and Python 3.9+ from the repository root:

```powershell
python -m pip install -r .\requirements-client-merge.txt
dotnet restore .\desktop\May.VpsDeploy.Tests\May.VpsDeploy.Tests.csproj --locked-mode
dotnet run --project .\desktop\May.VpsDeploy.Tests -c Release --no-restore -- $PWD
pwsh -NoProfile -File .\Start-VPSDeploy.ps1 -Mode ValidateProject
pwsh -NoProfile -File .\tests\Test-AuditFixes.ps1 -ProjectRoot $PWD
pwsh -NoProfile -File .\tests\Test-ClientCompatibility.ps1 -ProjectRoot $PWD
pwsh -NoProfile -File .\scripts\Test-NoSecrets.ps1 -ProjectRoot $PWD
```

`ValidateProject` runs the main regression entry, including GUI/update and available Python/Bash checks; do not run `Run-Tests.ps1` again merely to duplicate it. GUI checks need Windows STA and temporary current-user named pipes; restricted sandboxes may block the local credential bridge. Compatibility checks use fixed real client cores. Local tests create isolated temporary files and do not authorize production operations. `Start-VPSDeploy.cmd` opens the desktop shell; `Start-VPSDeploy.Cli.cmd` retains CLI navigation.

Build a local preview with `scripts/New-VpsReleasePackage.ps1 -Destination <output> -Development`. Formal packaging requires a clean main tree and stable application metadata with the new version; package creation does not authorize pushing or releasing. Keep update ownership limited to the manifest; never reset Git history or overwrite private/local/unmanaged files.

`tests/Test-DesktopInstaller.ps1` performs real install/update/uninstall tests using QA installers with no shortcuts or uninstall registry entries, under an isolated project fixture. CI runs this once in the Windows Python 3.13/runner job; do not duplicate all package tests across the matrix. Verify installers with native EXE startup and actual lifecycle behavior, not only file extensions or script parsing. Never deploy a QA installer as a release.

Scope local verification to the behavior changed. Run dedicated update/installer lifecycle verification when update code, the installer or release structure changes; ordinary UI changes do not require repeating it. Do not repeat public-release download probes when delivery metadata and assets have not changed.

## Coding Style & Naming Conventions

Follow surrounding formatting: four-space PowerShell/Python indentation, strict PowerShell error handling, and LF Bash files. Use existing `Verb-VpsNoun` functions, explicit parameter validation, and professional Chinese prompts. Preserve return/cancel semantics. Keep templates generic; retain legitimate custom configuration and fail closed on ambiguous layouts.

## Testing Guidelines

PowerShell uses assertion scripts named `Test-*.ps1`; Python uses `test_*.py`. Add behavior regressions for failures, cancellation, stale fingerprints, and rollback scope. Check Bash syntax and ShellCheck warnings. No numerical coverage threshold is specified. Simulated systemd and loopback tests do not prove production migration or WAN behavior.

## Commit, Pull Request & Security Guidelines

History contains concise Chinese subjects and `feat:`, `fix:`, or `test:` prefixes. Keep commits scoped. PRs should identify compatibility changes, verification, recovery behavior, and remaining gaps. Never commit `private/`, credentials, instance archives, local defaults, or signing materials. Controller-only recovery must not touch Tunnel; protocol recovery must not overwrite monitoring. Production upgrades, authoritative-config publication, proxy switches, and releases require explicit scope.
