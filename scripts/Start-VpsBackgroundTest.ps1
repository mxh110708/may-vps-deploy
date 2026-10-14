[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$ApplicationDirectory,
    [Parameter(Mandatory)][string]$FixtureRoot,
    [string]$PublicAssetRoot = $ApplicationDirectory,
    [object[]]$AllowedEndpoints = @(),
    [switch]$AllowManagementPortTransition,
    [switch]$AllowTransportFaults,
    [switch]$SyntheticFixture
)
$ErrorActionPreference = 'Stop'
if ($SyntheticFixture -and $AllowManagementPortTransition) { throw 'Synthetic UI suites cannot authorize management port transitions.' }
if ($AllowTransportFaults -and ($SyntheticFixture -or -not $AllowedEndpoints.Count)) { throw 'Transport fault tests require explicit test endpoints and a real isolated fixture.' }
$app = [IO.Path]::GetFullPath($ApplicationDirectory).TrimEnd('\','/')
$root = [IO.Path]::GetFullPath($FixtureRoot).TrimEnd('\','/')
$source = [IO.Path]::GetFullPath($PublicAssetRoot).TrimEnd('\','/')
if ($root -eq $app -or $root.StartsWith($app + '\', [StringComparison]::OrdinalIgnoreCase) -or $app.StartsWith($root + '\', [StringComparison]::OrdinalIgnoreCase)) { throw 'Test data must be independent of the application directory.' }
if (Test-Path -LiteralPath $root) { throw 'Choose a new, empty test directory. Existing data was preserved.' }
$exe = Join-Path $app 'MXH-VPS-Deploy.exe'
if (-not (Test-Path -LiteralPath $exe)) { throw 'Native application not found.' }
for ($candidate = $root; $candidate; $candidate = [IO.Path]::GetDirectoryName($candidate)) {
    if ((Test-Path -LiteralPath $candidate) -and ((Get-Item -LiteralPath $candidate -Force).Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw 'Test directory contains a link.' }
}
[IO.Directory]::CreateDirectory($root) | Out-Null
if ($IsWindows) {
    $access = [Security.AccessControl.DirectorySecurity]::new()
    $access.SetAccessRuleProtection($true, $false)
    $user = [Security.Principal.WindowsIdentity]::GetCurrent().User
    $access.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($user, 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow'))
    Set-Acl -LiteralPath $root -AclObject $access
}
# Only public runtime inputs, never private data or an archive locator.
foreach ($relative in @('config','assets','scripts','templates','vendor/test-cores','runtime/python','Fonts')) {
    $input = Join-Path $source $relative
    if (Test-Path -LiteralPath $input) {
        for ($candidate = $input; $candidate; $candidate = [IO.Path]::GetDirectoryName($candidate)) {
            if ((Get-Item -LiteralPath $candidate -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Public test input directory contains a link.' }
        }
        $output = Join-Path $root $relative
        foreach ($file in Get-ChildItem -LiteralPath $input -Recurse -Force) {
            if ($file.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Public test inputs contain a link.' }
            if ($file.PSIsContainer -or $file.Name -match '(?i)\.(local|private)\.' -or $file.FullName -match '[\\/]__pycache__[\\/]') { continue }
            $target=Join-Path $output ([IO.Path]::GetRelativePath($input,$file.FullName))
            [IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($target)) | Out-Null
            Copy-Item -LiteralPath $file.FullName -Destination $target
        }
    }
}
foreach ($relative in @('private','test-secrets','test-artifacts')) { [IO.Directory]::CreateDirectory((Join-Path $root $relative)) | Out-Null }
$sessionId = [guid]::NewGuid().ToString('N')
$token = [Convert]::ToHexString([Security.Cryptography.RandomNumberGenerator]::GetBytes(32)).ToLowerInvariant()
@{ IsolatedTestRoot = $true; SessionId = $sessionId } | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $root 'background-test.fixture.json') -Encoding utf8
$manifest = Join-Path $root 'test-session.private.json'
@{ SchemaVersion = 1; Root = $root; SessionId = $sessionId; PipeName = 'mxh-test-' + $sessionId; Token = $token; AllowedEndpoints = $AllowedEndpoints; AllowManagementPortTransition = [bool]$AllowManagementPortTransition; AllowTransportFaults = [bool]$AllowTransportFaults } | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $manifest -Encoding utf8
@{ Appearance = 'Dark'; FontId = 'Route'; AutoCheckUpdates = $false } | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $root 'private/desktop-settings.json') -Encoding utf8
if ($SyntheticFixture) {
    if ($AllowedEndpoints.Count) { throw 'Synthetic UI suites must not have remote targets.' }
    @{ schema_version = 1; synthetic_only = $true } | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $root 'qa-ui-review.fixture.json') -Encoding utf8
    $directory = Join-Path $root 'private/instances/Example/Managed-Demo/MXH-VPS-Deploy'
    [IO.Directory]::CreateDirectory($directory) | Out-Null
    @{ Provider='Example';Instance='Managed-Demo';NodeName='合成演示实例';Role='RealityEntry';Roles=@('RealityEntry');ActiveEntry='RealityEntry';Server=@{IPv4='192.0.2.10';IPv6='2001:db8::10';BootstrapSshPort=22};Ports=@{SshPrimary=22022;SshRescue=33022;XrayPrimary=443;XrayBackup=44443};Import=@{Status='Completed'};NetworkTuning=@{BandwidthMbps=100;ReferenceRttMs=0};ProtocolInventory=@{RealityEntry=@{Installed=$true;Enabled=$true}}} | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath (Join-Path $directory 'deployment-plan.json') -Encoding utf8
    @{ Engine='dotnet-v1';CurrentManagementPort=22022 } | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $directory 'deployment-state.json') -Encoding utf8
}
$start = [Diagnostics.ProcessStartInfo]::new($exe)
$start.UseShellExecute = $false; $start.CreateNoWindow = $true; $start.WindowStyle = [Diagnostics.ProcessWindowStyle]::Hidden
foreach ($arg in @('--test-session',$manifest,'--app-root',$root)) { $start.ArgumentList.Add($arg) }
$process = [Diagnostics.Process]::Start($start)
try {
    try { $process.PriorityClass = [Diagnostics.ProcessPriorityClass]::BelowNormal } catch { }
    $ready = Join-Path $root 'test-artifacts/ready.json'
    $until = [DateTimeOffset]::UtcNow.AddSeconds(25)
    while (-not (Test-Path -LiteralPath $ready)) {
        if ($process.HasExited) { throw 'Background app refused the session; check fixture inputs.' }
        if ([DateTimeOffset]::UtcNow -gt $until) { $process.Kill(); throw 'Background app startup timed out.' }
        Start-Sleep -Milliseconds 100
    }
    [pscustomobject]@{ SessionManifest = $manifest; ProcessId = $process.Id; Artifacts = (Join-Path $root 'test-artifacts') }
} finally { $process.Dispose() }
