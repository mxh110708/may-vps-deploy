#requires -Version 7.4
[CmdletBinding()]
param([Parameter(Mandatory)][string]$ProjectRoot)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$paths = @(& git -c "safe.directory=$ProjectRoot" -C $ProjectRoot ls-files --cached --others --exclude-standard -- '*.ps1' '*.psm1')
if ($LASTEXITCODE -ne 0) { throw 'Cannot enumerate PowerShell sources.' }
foreach ($relative in $paths) {
    $path = Join-Path $ProjectRoot $relative
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { continue }
    $tokens = $null; $parseErrors = $null
    [Management.Automation.Language.Parser]::ParseFile($path, [ref]$tokens, [ref]$parseErrors) | Out-Null
    if ($parseErrors.Count) { throw "PowerShell parse failed: $relative" }
}
& (Join-Path $ProjectRoot 'scripts/Test-NoSecrets.ps1') -ProjectRoot $ProjectRoot
Write-Host "PowerShell syntax passed: $($paths.Count) sources"
