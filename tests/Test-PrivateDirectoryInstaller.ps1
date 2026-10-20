#requires -Version 7.4
[CmdletBinding()]
param([string]$ProjectRoot=(Split-Path -Parent $PSScriptRoot),[Parameter(Mandatory)][string]$PackageJson,[string]$EvidenceDirectory)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$ProjectRoot=[IO.Path]::GetFullPath($ProjectRoot)
$package=Get-Content -Raw -LiteralPath $PackageJson|ConvertFrom-Json -AsHashtable
if(-not $IsWindows -or -not $package.TestBuild){throw 'This test requires a Windows QA installer without registration or shortcuts.'}
$fixture=Join-Path $ProjectRoot ('.test-output/private-directory-installer-'+[guid]::NewGuid().ToString('N'))
$app=Join-Path $fixture '应用';$custom=Join-Path $fixture '私人归档';$passed=0
function Assert-Private([bool]$Value,[string]$Message){if(-not $Value){throw $Message};$script:passed++}
function Invoke-Private([string]$Exe,[string[]]$Arguments){
 $start=[Diagnostics.ProcessStartInfo]::new($Exe);$start.UseShellExecute=$false;$start.CreateNoWindow=$true
 foreach($argument in $Arguments){$start.ArgumentList.Add($argument)}
 $process=[Diagnostics.Process]::Start($start)
 try{if(-not $process.WaitForExit(120000)){$process.Kill($true);throw 'QA process timed out.'};return $process.ExitCode}finally{$process.Dispose()}
}
try{
 [IO.Directory]::CreateDirectory($fixture)|Out-Null
 $installArguments=@('/SP-','/VERYSILENT','/SUPPRESSMSGBOXES','/NORESTART','/NOICONS',('/DIR='+$app))
 Assert-Private ((Invoke-Private $package.Installer $installArguments) -eq 0) 'initial isolated installation failed'
 @{synthetic_only=$true}|ConvertTo-Json|Set-Content -LiteralPath (Join-Path $app 'qa-ui-review.fixture.json') -Encoding utf8
 [IO.Directory]::CreateDirectory((Join-Path $app 'private'))|Out-Null
 @{Appearance='Dark';AutoCheckUpdates=$false;FontId='Route'}|ConvertTo-Json|Set-Content -LiteralPath (Join-Path $app 'private/desktop-settings.json') -Encoding utf8
 'synthetic archive payload'|Set-Content -LiteralPath (Join-Path $app 'private/record.txt')
 $hash=(Get-FileHash -LiteralPath (Join-Path $app 'private/record.txt')).Hash
 $proof=Join-Path $app '.tmp/storage-ui/runtime-proof.json'
 [IO.Directory]::CreateDirectory((Split-Path -Parent $proof))|Out-Null
 $uiExit=Invoke-Private (Join-Path $app 'May-VPS-Deploy.exe') @('--ui-smoke',$proof,'--app-root',$app,'--exercise-storage')
 if($uiExit -ne 0 -and (Test-Path -LiteralPath $proof)){Get-Content -Raw -LiteralPath $proof|Write-Host}
 if($uiExit -ne 0 -and (Test-Path -LiteralPath ($proof+'.startup.txt'))){Get-Content -LiteralPath ($proof+'.startup.txt')|Select-Object -Last 15|Write-Host}
 Assert-Private ($uiExit -eq 0) 'native storage and node picker regression failed'
 $ui=Get-Content -Raw -LiteralPath (Join-Path $app '.tmp/storage-ui/storage-regression-proof.json')|ConvertFrom-Json
 Assert-Private ($ui.migration_roundtrip -and $ui.backup_opt_in -and $ui.select_and_clear_visible -and $ui.custom_font_rendered) 'storage regression proof incomplete'
 if($EvidenceDirectory){
  $evidence=[IO.Path]::GetFullPath($EvidenceDirectory);$boundary=[IO.Path]::GetFullPath((Join-Path $ProjectRoot '.tmp')).TrimEnd('\')+'\'
  if(-not $evidence.StartsWith($boundary,[StringComparison]::OrdinalIgnoreCase)){throw 'Evidence must stay in project .tmp.'}
  [IO.Directory]::CreateDirectory($evidence)|Out-Null
  foreach($file in Get-ChildItem -LiteralPath (Join-Path $app '.tmp/storage-ui') -File){Copy-Item -LiteralPath $file.FullName -Destination (Join-Path $evidence $file.Name)}
 }
 Remove-Item -LiteralPath (Join-Path $app 'qa-ui-review.fixture.json')
 # All movement and deletion stays inside the explicitly verified QA fixture.
 $old=[IO.Path]::GetFullPath((Join-Path $app 'private'));$custom=[IO.Path]::GetFullPath($custom)
 if(-not $old.StartsWith($fixture+'\',[StringComparison]::OrdinalIgnoreCase) -or -not $custom.StartsWith($fixture+'\',[StringComparison]::OrdinalIgnoreCase)){throw 'Unsafe fixture movement.'}
 Move-Item -LiteralPath $old -Destination $custom
 $id=[guid]::NewGuid().ToString('N')
 @{SchemaVersion=1;OwnerId=$id;AppRoot=$app}|ConvertTo-Json|Set-Content -LiteralPath (Join-Path $custom '.may-private-directory.json') -Encoding utf8
 @{SchemaVersion=1;OwnerId=$id;Directory=$custom}|ConvertTo-Json|Set-Content -LiteralPath (Join-Path $app 'archive-location.private.json') -Encoding utf8
 Assert-Private ((Invoke-Private $package.Installer $installArguments) -eq 0) 'in-place installation with external archive failed'
 Assert-Private ((Get-FileHash -LiteralPath (Join-Path $custom 'record.txt')).Hash -eq $hash) 'in-place installation changed archive'
 Assert-Private ((Invoke-Private (Join-Path $app 'unins000.exe') @('/VERYSILENT','/SUPPRESSMSGBOXES','/NORESTART')) -eq 0) 'keep-data uninstall failed'
 Assert-Private ((Test-Path -LiteralPath (Join-Path $app 'archive-location.private.json')) -and (Get-FileHash -LiteralPath (Join-Path $custom 'record.txt')).Hash -eq $hash) 'keep-data uninstall lost archive or locator'
 Assert-Private ((Invoke-Private $package.Installer $installArguments) -eq 0) 'reinstallation with preserved custom archive failed'
 $marker=Join-Path $custom '.may-private-directory.json';$original=[IO.File]::ReadAllBytes($marker)
 @{SchemaVersion=1;OwnerId=[guid]::NewGuid().ToString('N');AppRoot=$app}|ConvertTo-Json|Set-Content -LiteralPath $marker -Encoding utf8
 Assert-Private ((Invoke-Private (Join-Path $app 'unins000.exe') @('/VERYSILENT','/SUPPRESSMSGBOXES','/NORESTART','/REMOVEDATA=1')) -ne 0) 'uninstall accepted mismatching archive ownership'
 Assert-Private ((Test-Path -LiteralPath (Join-Path $app 'May-VPS-Deploy.exe')) -and (Get-FileHash -LiteralPath (Join-Path $custom 'record.txt')).Hash -eq $hash) 'blocked uninstall modified app or data'
 [IO.File]::WriteAllBytes($marker,$original)
 $outside=Join-Path $fixture 'unrelated.txt';'keep unrelated file'|Set-Content -LiteralPath $outside
 $uninstallLog=Join-Path $fixture 'remove-data.log'
 Assert-Private ((Invoke-Private (Join-Path $app 'unins000.exe') @('/VERYSILENT','/SUPPRESSMSGBOXES','/NORESTART','/REMOVEDATA=1',('/LOG='+$uninstallLog))) -eq 0) 'remove-data uninstall failed'
 $watch=[Diagnostics.Stopwatch]::StartNew();while((Test-Path -LiteralPath $custom) -and $watch.ElapsedMilliseconds -lt 15000){[Threading.Thread]::Sleep(100)}
 if(Test-Path -LiteralPath $custom){Get-Content -LiteralPath $uninstallLog|Select-Object -Last 18|Write-Host}
 Assert-Private (-not(Test-Path -LiteralPath $custom) -and (Test-Path -LiteralPath $outside)) 'uninstall removal boundary failed'
 Write-Host "PASS: $passed custom private directory, WinUI picker and installer assertions; no production connections."
}finally{
 $boundary=[IO.Path]::GetFullPath((Join-Path $ProjectRoot '.test-output')).TrimEnd('\')+'\'
 if(-not [IO.Path]::GetFullPath($fixture).StartsWith($boundary,[StringComparison]::OrdinalIgnoreCase)){throw 'Unsafe fixture cleanup.'}
 if(Test-Path -LiteralPath $fixture){Remove-Item -LiteralPath $fixture -Recurse -Force}
}
