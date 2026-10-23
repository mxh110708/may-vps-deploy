[CmdletBinding()]
param([Parameter(Mandatory)][string]$ProjectRoot, [string]$MayRouteCorePath)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $ProjectRoot 'src/VpsDeploy.Core.psm1') -Force
$work = Join-Path $ProjectRoot ('.tmp/client-compatibility-' + [guid]::NewGuid().ToString('N'))
[IO.Directory]::CreateDirectory($work) | Out-Null
$module = Get-Module VpsDeploy.Core
$template = Join-Path $ProjectRoot 'templates/client/sing-box-general.template.json'
$originalHash = (Get-FileHash -LiteralPath $template -Algorithm SHA256).Hash
$validationPath = New-MxhSingBoxValidationConfig -ProjectRoot $ProjectRoot -ConfigPath $template -DataDirectory $work
$value = Get-Content -Raw -LiteralPath $validationPath | ConvertFrom-Json -AsHashtable
if (@($value.route.rule_set | Where-Object type -eq 'local').Count -ne 5) { throw 'Known public rules must validate offline.' }
if ($originalHash -ne (Get-FileHash -LiteralPath $template -Algorithm SHA256).Hash) { throw 'Offline validation changed the portable template.' }

$officialCore = Get-VpsBundledClientCore -ProjectRoot $ProjectRoot -Core 'sing-box'
$cores = @($officialCore)
if ($MayRouteCorePath) { $cores += $MayRouteCorePath }
foreach ($core in $cores) {
    $result = Invoke-MxhSingBoxCandidateCheck -ProjectRoot $ProjectRoot -CorePath $core -ConfigPath $template
    if ($result.ExitCode -ne 0) { throw "Client template compatibility failed: $($result.StdErr)" }
}
$clash = Join-Path $ProjectRoot 'templates/client/clash-general.template.yaml'
$mihomo = Get-VpsBundledClientCore -ProjectRoot $ProjectRoot -Core mihomo
$result = Invoke-MxhMihomoCandidateCheck -ProjectRoot $ProjectRoot -CorePath $mihomo -ConfigPath $clash -DataDirectory (Join-Path $work 'mihomo')
if ($result.ExitCode -ne 0) { throw "Clash template compatibility failed: $($result.StdErr)" }

# Build a real synthetic pair and validate it, not only the empty base templates.
$candidate = & $module {
    param($Root, $Output)
    $scheme = New-MxhClientScheme $Root
    $key = [Convert]::ToBase64String([byte[]](1..32)).TrimEnd('=').Replace('+','-').Replace('/','_')
    $node = @{name='Fixture-Entry';kind='entry';region_group=$scheme.Layout.region_groups[0];transit_group=$null;
        clash=@{name='Fixture-Entry';type='vless';server='192.0.2.20';port=443;uuid='00000000-0000-0000-0000-000000000000';flow='xtls-rprx-vision';servername='edge.example.invalid';tls=$true;udp=$true;'client-fingerprint'='chrome';'reality-opts'=@{'public-key'=$key;'short-id'='abcd'}};
        sing_box=@{tag='Fixture-Entry';type='vless';server='192.0.2.20';server_port=443;uuid='00000000-0000-0000-0000-000000000000';flow='xtls-rprx-vision';tls=@{enabled=$true;server_name='edge.example.invalid';utls=@{enabled=$true;fingerprint='chrome'};reality=@{enabled=$true;public_key=$key;short_id='abcd'}}}}
    $scheme.Entries = @(@{Id='fixture';Node=$node;Source=@{Kind='Manual'}})
    Invoke-MxhSchemeBuild $scheme $Root -OutputRoot $Output
    return $scheme.Candidate
} $ProjectRoot (Join-Path $work 'generated')
foreach ($core in $cores) {
    $result = Invoke-MxhSingBoxCandidateCheck -ProjectRoot $ProjectRoot -CorePath $core -ConfigPath $candidate.SingBox
    if ($result.ExitCode -ne 0) { throw "Generated configuration compatibility failed: $($result.StdErr)" }
}
$academicPython = Get-Command python -ErrorAction Stop
$academicResult = Invoke-VpsProcess -FilePath $academicPython.Source -ArgumentList @(
    (Join-Path $ProjectRoot 'tests/academic-routing-native.py'), '--sing-box', $officialCore, '--mihomo', $mihomo
) -TimeoutSeconds 60
if ($academicResult.ExitCode -ne 0) { throw "Actual academic routing checks failed: $($academicResult.StdErr) $($academicResult.StdOut)" }
Write-Host $academicResult.StdOut.Trim()
Write-Host "Client compatibility passed: official core, Mihomo, five offline rules, generated pair, actual academic routing; May Route core included=$([bool]$MayRouteCorePath)"
