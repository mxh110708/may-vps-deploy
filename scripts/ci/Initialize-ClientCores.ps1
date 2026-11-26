#requires -Version 7.4
[CmdletBinding()]
param([Parameter(Mandatory)][string]$ProjectRoot, [switch]$Xray, [switch]$CheckConfigs, [switch]$AddressRuntime)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $ProjectRoot 'src/VpsDeploy.Core.psm1') -Force
$singBox = Get-VpsBundledClientCore -ProjectRoot $ProjectRoot -Core sing-box
$null = Get-VpsBundledClientCore -ProjectRoot $ProjectRoot -Core mihomo
if ($Xray -or $AddressRuntime) {
    $directory = Join-Path $ProjectRoot '.cache/ci-xray/26.3.27'
    [IO.Directory]::CreateDirectory($directory) | Out-Null
    $archive = Join-Path $directory 'Xray-windows-64.zip'
    if (-not (Test-Path -LiteralPath $archive)) {
        Invoke-WebRequest -Uri 'https://github.com/XTLS/Xray-core/releases/download/v26.3.27/Xray-windows-64.zip' -OutFile $archive -TimeoutSec 120
    }
    if ((Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash -ne 'd004c39288ce9ada487c6f398c7c545f7d749e44bdfdd59dbc9f865afba4e1ad') { throw 'Fixed Xray archive digest mismatch.' }
    $coreDirectory = Join-Path $directory 'core'
    Expand-Archive -LiteralPath $archive -DestinationPath $coreDirectory -Force
    $executable = Join-Path $coreDirectory 'xray.exe'
    if ((Get-FileHash -LiteralPath $executable -Algorithm SHA256).Hash -ne '15c2d007954ac53ba69b80ec91242786b3c0b71d52649165b4ca1d5cc96ef8f1') { throw 'Fixed Xray executable digest mismatch.' }
    if ($env:GITHUB_ENV) { "MAY_TEST_XRAY=$executable" | Out-File -FilePath $env:GITHUB_ENV -Encoding utf8 -Append }
    # The Python runner and its child steps also need the value within this process.
    $env:MAY_TEST_XRAY = $executable
}
if ($CheckConfigs) {
    & (Join-Path $ProjectRoot 'tests/Test-SingBoxConfig.ps1') -ProjectRoot $ProjectRoot -SingBoxPath $singBox
    & (Join-Path $ProjectRoot 'tests/Test-ClientCompatibility.ps1') -ProjectRoot $ProjectRoot
}
if ($AddressRuntime) {
    $evidenceDirectory = Join-Path $ProjectRoot '.tmp/ci'
    [IO.Directory]::CreateDirectory($evidenceDirectory) | Out-Null
    & python (Join-Path $ProjectRoot 'tests/outbound-address-runtime44.py') --sing-box $singBox --xray $executable --output (Join-Path $evidenceDirectory 'address44.json')
    if ($LASTEXITCODE -ne 0) { throw 'Address-family runtime acceptance failed.' }
}
