#requires -Version 7.4
[CmdletBinding()]
param([Parameter(Mandatory)][string]$ProjectRoot)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
Import-Module (Join-Path $ProjectRoot 'src/VpsDeploy.Update.psm1') -Force
$updateModule=Get-Module VpsDeploy.Update
$passed=0
function Assert-Update { param([bool]$Condition,[string]$Message) if(-not $Condition){throw "UPDATE ASSERT: $Message"};$script:passed++ }
function Assert-UpdateThrows { param([scriptblock]$Action,[string]$Message) $thrown=$false;try{& $Action}catch{$thrown=$true};Assert-Update $thrown $Message }
function New-UpdateFixture {
    param([string]$Directory,[string]$Version,[hashtable]$Extra)
    [IO.Directory]::CreateDirectory((Join-Path $Directory 'config'))|Out-Null
    @{version=$Version;channel='stable'}|ConvertTo-Json|Set-Content (Join-Path $Directory 'config/application.json')
    foreach($entry in $Extra.GetEnumerator()){[IO.Directory]::CreateDirectory((Split-Path -Parent (Join-Path $Directory $entry.Key)))|Out-Null;[IO.File]::WriteAllText((Join-Path $Directory $entry.Key),[string]$entry.Value)}
    $files=@(Get-ChildItem -LiteralPath $Directory -File -Recurse|ForEach-Object{@{path=[IO.Path]::GetRelativePath($Directory,$_.FullName).Replace('\','/');sha256=(Get-FileHash -LiteralPath $_.FullName).Hash.ToLowerInvariant()}})
    @{schema_version=1;version=$Version;files=$files}|ConvertTo-Json -Depth 10|Set-Content (Join-Path $Directory 'application-files.json')
}
function New-UpdateZip {
    param([string]$Path,[Collections.IDictionary]$Entries)
    $zip=[IO.Compression.ZipFile]::Open($Path,[IO.Compression.ZipArchiveMode]::Create)
    try {foreach($entry in $Entries.GetEnumerator()){$item=$zip.CreateEntry($entry.Key);$writer=[IO.StreamWriter]::new($item.Open());try{$writer.Write([string]$entry.Value)}finally{$writer.Dispose()}}}finally{$zip.Dispose()}
}
function Invoke-FixtureGit {param([string[]]$Arguments)& git -c "safe.directory=$gitFixture" -C $gitFixture @Arguments 2>$null|Out-Null;if($LASTEXITCODE -ne 0){throw 'Fixture git failed.'}}
$fixture=Join-Path $ProjectRoot ('.test-output/app-update-'+[guid]::NewGuid().ToString('N'))
[IO.Directory]::CreateDirectory($fixture)|Out-Null
try {
    foreach($path in @('../escape.txt','/absolute.txt','folder/../escape.txt','private/plan.json','config/app-defaults.local.json','folder/secret.private.json','id_ed25519','file.pem','CON.txt','folder\file.ps1','folder/file.','folder/file ')) {
        Assert-UpdateThrows {Assert-VpsApplicationFilePath $path} 'unsafe/private paths rejected'
    }
    Assert-VpsUpdateAssetUri 'https://github.com/mxh110708/may-vps-deploy/releases/download/v1.1.0/app.zip' 'v1.1.0'
    Assert-Update $true 'official asset URL accepted'
    Assert-UpdateThrows {Assert-VpsUpdateAssetUri 'https://example.invalid/mxh110708/may-vps-deploy/releases/download/v1.1.0/app.zip' 'v1.1.0'} 'foreign download rejected'
    $old=Join-Path $fixture 'old';$new=Join-Path $fixture 'new'
    New-UpdateFixture $old '1.0.0' @{'main.ps1'='old';'obsolete.txt'='old-only'}
    New-UpdateFixture $new '1.1.0' @{'main.ps1'='new';'added.txt'='new-only'}
    [IO.Directory]::CreateDirectory((Join-Path $old 'private/instances'))|Out-Null
    'fixture-private-data'|Set-Content (Join-Path $old 'private/instances/record.txt')
    'fixture-local-settings'|Set-Content (Join-Path $old 'config/app-defaults.local.json')
    'unmanaged'|Set-Content (Join-Path $old 'notes.txt')
    $privateHash=(Get-FileHash (Join-Path $old 'private/instances/record.txt')).Hash
    $localHash=(Get-FileHash (Join-Path $old 'config/app-defaults.local.json')).Hash
    $archive=Join-Path $fixture 'valid.zip';[IO.Compression.ZipFile]::CreateFromDirectory($new,$archive)
    $unpacked=Join-Path $fixture 'unpacked'
    $manifest=Expand-VpsVerifiedApplicationPackage $archive $unpacked
    Assert-Update ($manifest.version -eq '1.1.0') 'complete release verified'
    Install-VpsPortableApplicationUpdate $old $unpacked (Join-Path $fixture 'rollback-success')
    Assert-Update ((Get-VpsApplicationVersion $old).ToString() -eq '1.1.0') 'portable version replaced in place'
    Assert-Update ((Get-Content (Join-Path $old 'main.ps1')) -eq 'new' -and -not (Test-Path (Join-Path $old 'obsolete.txt'))) 'owned changes and obsolete file handled'
    Assert-Update ((Get-FileHash (Join-Path $old 'private/instances/record.txt')).Hash -eq $privateHash) 'private archives unchanged'
    Assert-Update ((Get-FileHash (Join-Path $old 'config/app-defaults.local.json')).Hash -eq $localHash -and (Get-Content (Join-Path $old 'notes.txt')) -eq 'unmanaged') 'local defaults and unknown files unchanged'
    Assert-UpdateThrows {Install-VpsPortableApplicationUpdate $old $unpacked (Join-Path $fixture 'rollback-repeat')} 'same version refused'

    $modified=Join-Path $fixture 'modified'
    New-UpdateFixture $modified '1.0.0' @{'main.ps1'='old'}
    'user edit'|Set-Content (Join-Path $modified 'main.ps1')
    Assert-UpdateThrows {Install-VpsPortableApplicationUpdate $modified $unpacked (Join-Path $fixture 'rollback-modified')} 'managed user changes block update'
    Assert-Update ((Get-Content (Join-Path $modified 'main.ps1')) -eq 'user edit') 'user edit preserved'
    $collision=Join-Path $fixture 'collision'
    New-UpdateFixture $collision '1.0.0' @{'main.ps1'='old'}
    'user file'|Set-Content (Join-Path $collision 'added.txt')
    Assert-UpdateThrows {Install-VpsPortableApplicationUpdate $collision $unpacked (Join-Path $fixture 'rollback-collision')} 'new file collision blocks update'
    Assert-Update ((Get-Content (Join-Path $collision 'added.txt')) -eq 'user file') 'collision does not overwrite unknown data'

    $failure=Join-Path $fixture 'failure'
    New-UpdateFixture $failure '1.0.0' @{'main.ps1'='old'}
    $before=(Get-FileHash (Join-Path $failure 'config/application.json')).Hash
    & $updateModule {
        param($Old,$New,$Recovery)
        $script:FailCopySource=Join-Path $New 'main.ps1'
        function Copy-Item {param([string]$LiteralPath,[string]$Destination,[switch]$Force)
            if($LiteralPath -eq $script:FailCopySource){throw 'fixture copy failure'}
            Microsoft.PowerShell.Management\Copy-Item @PSBoundParameters
        }
        try {Install-VpsPortableApplicationUpdate $Old $New $Recovery;throw 'Expected update failure.'}
        catch {if($_.Exception.Message -eq 'Expected update failure.'){throw}}
        finally {Remove-Item Function:\Copy-Item;Remove-Variable FailCopySource -Scope Script}
    } $failure $unpacked (Join-Path $fixture 'rollback-failure')
    Assert-Update ((Get-FileHash (Join-Path $failure 'config/application.json')).Hash -eq $before -and (Get-Content (Join-Path $failure 'main.ps1')) -eq 'old') 'mid-update failure restores prior owned files'
    Assert-Update (-not (Test-Path (Join-Path $failure 'added.txt'))) 'failed update removes newly created files'

    $duplicates=[Collections.Generic.Dictionary[string,string]]::new([StringComparer]::Ordinal);$duplicates['same.txt']='a';$duplicates['SAME.txt']='b'
    foreach($bad in @(@{Name='traversal';Entries=@{'../escape.txt'='bad'}},@{Name='directory-traversal';Entries=@{'../escape/'=''}},@{Name='private';Entries=@{'private/record.txt'='bad'}},@{Name='duplicate';Entries=$duplicates})) {
        $zip=Join-Path $fixture ($bad.Name+'.zip');New-UpdateZip $zip $bad.Entries
        Assert-UpdateThrows {Expand-VpsVerifiedApplicationPackage $zip (Join-Path $fixture ($bad.Name+'-out'))} 'unsafe ZIP rejected'
    }
    Assert-Update (-not (Test-Path (Join-Path $fixture 'escape.txt'))) 'ZIP traversal never writes outside target'
    'tamper'|Set-Content (Join-Path $new 'main.ps1')
    $badHash=Join-Path $fixture 'bad-hash.zip';[IO.Compression.ZipFile]::CreateFromDirectory($new,$badHash)
    Assert-UpdateThrows {Expand-VpsVerifiedApplicationPackage $badHash (Join-Path $fixture 'bad-hash-out')} 'tampered release rejected'

    $release=@{tag_name='v1.1.0';draft=$false;prerelease=$false;body='Fixture notes';html_url='https://github.com/mxh110708/may-vps-deploy/releases/tag/v1.1.0';assets=@()}
    $info=& $updateModule {param($Root,$Release)
        $script:FixtureRelease=$Release
        function Invoke-RestMethod {return $script:FixtureRelease}
        try {Get-VpsApplicationUpdate $Root}finally{Remove-Item Function:\Invoke-RestMethod;Remove-Variable FixtureRelease -Scope Script}
    } $old $release
    Assert-Update (-not $info.Available -and $info.Version -eq '1.1.0') 'same release works without new update contract'
    $release.tag_name='v1.2.0'
    Assert-UpdateThrows {& $updateModule {param($Root,$Release)
        $script:FixtureRelease=$Release;function Invoke-RestMethod {return $script:FixtureRelease}
        try {Get-VpsApplicationUpdate $Root}finally{Remove-Item Function:\Invoke-RestMethod;Remove-Variable FixtureRelease -Scope Script}
    } $old $release} 'new release without complete verified assets rejected'

    $installed=Join-Path $fixture 'installed-contract'
    New-UpdateFixture $installed '1.0.0' @{'main.ps1'='installed app'}
    @{schema_version=1;type='installed';app_id='may-vps-deploy-desktop';version='1.0.0'}|ConvertTo-Json|Set-Content (Join-Path $installed 'installation.json')
    Assert-Update ((Get-VpsApplicationDistribution $installed) -eq 'Installed') 'installed marker selects installer update mode'
    $installerRelease=@{tag_name='v1.1.0';draft=$false;prerelease=$false;body='Fixture installer';html_url='https://github.com/mxh110708/may-vps-deploy/releases/tag/v1.1.0';assets=@()}
    foreach($name in @('may-vps-deploy-v1.1.0-windows-amd64.zip','SHA256SUMS.txt','may-vps-deploy-v1.1.0-windows-amd64-setup.exe','may-vps-deploy-v1.1.0-windows-amd64.files.json')){
        $installerRelease.assets+=@{name=$name;size=20;digest=('sha256:'+('a'*64));browser_download_url=('https://github.com/mxh110708/may-vps-deploy/releases/download/v1.1.0/'+$name)}
    }
    $installerInfo=& $updateModule {param($Root,$Release)
        $script:FixtureRelease=$Release;function Invoke-RestMethod {return $script:FixtureRelease}
        try{Get-VpsApplicationUpdate $Root}finally{Remove-Item Function:\Invoke-RestMethod;Remove-Variable FixtureRelease -Scope Script}
    } $installed $installerRelease
    Assert-Update ($installerInfo.Available -and $installerInfo.Distribution -eq 'Installed' -and $installerInfo.Installer.name.EndsWith('-setup.exe')) 'installed app selects verified setup EXE and file manifest'
    $installerRelease.assets[2].browser_download_url='https://example.invalid/installer.exe'
    Assert-UpdateThrows {& $updateModule {param($Root,$Release)
        $script:FixtureRelease=$Release;function Invoke-RestMethod {return $script:FixtureRelease}
        try{Get-VpsApplicationUpdate $Root}finally{Remove-Item Function:\Invoke-RestMethod;Remove-Variable FixtureRelease -Scope Script}
    } $installed $installerRelease} 'installer download cannot leave official release path'
    $installerRelease.assets=@($installerRelease.assets|Where-Object name -notlike '*.files.json')
    Assert-UpdateThrows {& $updateModule {param($Root,$Release)
        $script:FixtureRelease=$Release;function Invoke-RestMethod {return $script:FixtureRelease}
        try{Get-VpsApplicationUpdate $Root}finally{Remove-Item Function:\Invoke-RestMethod;Remove-Variable FixtureRelease -Scope Script}
    } $installed $installerRelease} 'installed update requires complete file ownership manifest'
    @{schema_version=1;type='installed';app_id='other-app'}|ConvertTo-Json|Set-Content (Join-Path $installed 'installation.json')
    Assert-UpdateThrows {Get-VpsApplicationDistribution $installed} 'invalid installer marker cannot fall back to destructive portable update'

    $gitFixture=Join-Path $fixture 'git';[IO.Directory]::CreateDirectory((Join-Path $gitFixture 'config'))|Out-Null
    Invoke-FixtureGit @('init','-b','main');Invoke-FixtureGit @('config','user.name','Update Fixture');Invoke-FixtureGit @('config','user.email','fixture@example.invalid')
    "private/`n*.local.json`n.tmp/"|Set-Content (Join-Path $gitFixture '.gitignore')
    @{version='1.0.0';channel='stable'}|ConvertTo-Json|Set-Content (Join-Path $gitFixture 'config/application.json')
    'old'|Set-Content (Join-Path $gitFixture 'main.ps1')
    Invoke-FixtureGit @('add','.');Invoke-FixtureGit @('commit','-m','fixture old');Invoke-FixtureGit @('switch','-c','release-fixture')
    @{version='1.1.0';channel='stable'}|ConvertTo-Json|Set-Content (Join-Path $gitFixture 'config/application.json')
    'new'|Set-Content (Join-Path $gitFixture 'main.ps1')
    Invoke-FixtureGit @('add','.');Invoke-FixtureGit @('commit','-m','fixture new');Invoke-FixtureGit @('tag','v1.1.0');Invoke-FixtureGit @('switch','main')
    [IO.Directory]::CreateDirectory((Join-Path $gitFixture 'private'))|Out-Null
    'keep private'|Set-Content (Join-Path $gitFixture 'private/record.txt')
    'dirty'|Add-Content (Join-Path $gitFixture 'main.ps1')
    Assert-UpdateThrows {Assert-VpsGitApplicationClean $gitFixture} 'dirty Git worktree blocked'
    Invoke-FixtureGit @('restore','main.ps1')
    Complete-VpsGitApplicationUpdate $gitFixture 'v1.1.0' '1.1.0'
    Assert-Update ((Get-VpsApplicationVersion $gitFixture).ToString() -eq '1.1.0') 'Git use copy fast-forwards to exact release'
    Assert-Update ((Get-Content (Join-Path $gitFixture 'private/record.txt')) -eq 'keep private') 'Git update preserves ignored private data'
    if($IsWindows){
        $helperRoot=Join-Path $fixture 'helper-app';$helperPackage=Join-Path $fixture 'helper-package'
        $launcher="[IO.File]::WriteAllText((Join-Path `$PSScriptRoot 'private/restarted.txt'),'restarted')"
        New-UpdateFixture $helperRoot '1.0.0' @{'Start-VPSDeploy.Gui.ps1'=$launcher}
        New-UpdateFixture $helperPackage '1.1.0' @{'Start-VPSDeploy.Gui.ps1'=$launcher}
        [IO.Directory]::CreateDirectory((Join-Path $helperRoot 'private'))|Out-Null
        'keep helper private'|Set-Content (Join-Path $helperRoot 'private/record.txt')
        $stage=Join-Path $helperRoot ('.tmp/app-update-'+[guid]::NewGuid().ToString('N'))
        [IO.Directory]::CreateDirectory($stage)|Out-Null
        Copy-Item -LiteralPath $helperPackage -Destination (Join-Path $stage 'package') -Recurse
        Copy-Item -LiteralPath (Join-Path $ProjectRoot 'scripts/Complete-VpsAppUpdate.ps1') -Destination $stage
        Copy-Item -LiteralPath (Join-Path $ProjectRoot 'src/VpsDeploy.Update.psm1') -Destination $stage
        $exitStart=[Diagnostics.ProcessStartInfo]::new((Join-Path $PSHOME 'pwsh.exe'));$exitStart.UseShellExecute=$false;$exitStart.CreateNoWindow=$true
        foreach($argument in @('-NoProfile','-Command','exit 0')){$exitStart.ArgumentList.Add($argument)}
        $exited=[Diagnostics.Process]::Start($exitStart);[void]$exited.WaitForExit(10000);$parentPid=$exited.Id;$exited.Dispose()
        $jobPath=Join-Path $stage 'update-job.private.json'
        @{ProjectRoot=$helperRoot;Stage=$stage;Package=(Join-Path $stage 'package');Version='1.1.0';Tag='v1.1.0';ParentPid=$parentPid;Proxy=''}|ConvertTo-Json|Set-Content $jobPath
        $start=[Diagnostics.ProcessStartInfo]::new((Join-Path $PSHOME 'pwsh.exe'));$start.UseShellExecute=$false;$start.CreateNoWindow=$true
        foreach($argument in @('-NoProfile','-STA','-WindowStyle','Hidden','-File',(Join-Path $stage 'Complete-VpsAppUpdate.ps1'),'-JobPath',$jobPath)){$start.ArgumentList.Add($argument)}
        $helper=[Diagnostics.Process]::Start($start)
        try{
            if(-not $helper.WaitForExit(15000)){$helper.Kill($true);throw 'Isolated update helper timed out.'}
            Assert-Update ($helper.ExitCode -eq 0 -and -not(Test-Path $stage)) 'actual helper completes and removes temporary recovery copies'
            $restart=Join-Path $helperRoot 'private/restarted.txt';$watch=[Diagnostics.Stopwatch]::StartNew()
            while(-not(Test-Path $restart) -and $watch.ElapsedMilliseconds -lt 10000){[Threading.Thread]::Sleep(20)}
            Assert-Update (Test-Path $restart) 'actual helper launches updated desktop entry'
            Assert-Update ((Get-VpsApplicationVersion $helperRoot).ToString() -eq '1.1.0' -and (Get-Content (Join-Path $helperRoot 'private/record.txt')) -eq 'keep helper private') 'helper updates app while preserving private data'
        }finally{$helper.Dispose()}
    }
    Write-Host "Application update passed: $passed assertions" -ForegroundColor Green
} finally {
    $prefix=[IO.Path]::GetFullPath((Join-Path $ProjectRoot '.test-output'))+[IO.Path]::DirectorySeparatorChar
    if(-not [IO.Path]::GetFullPath($fixture).StartsWith($prefix,[StringComparison]::OrdinalIgnoreCase)){throw 'Unsafe update fixture cleanup.'}
    Remove-Item -LiteralPath $fixture -Recurse -Force
}
