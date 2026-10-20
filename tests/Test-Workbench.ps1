[CmdletBinding()]
param([Parameter(Mandatory)][string]$ProjectRoot)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
Import-Module (Join-Path $ProjectRoot 'src/VpsDeploy.Core.psm1') -Force
$module=Get-Module VpsDeploy.Core
& $module {
    param($root)
    $script:workbenchChecks=0
    function Check($condition,$message){if(-not $condition){throw "Workbench regression: $message"};$script:workbenchChecks++}
    function Fails([scriptblock]$action,$message){$failed=$false;try{& $action|Out-Null}catch{$failed=$true};Check $failed $message}
    $temporary=Join-Path $root ('.tmp/workbench-'+[Guid]::NewGuid().ToString('N'))
    [IO.Directory]::CreateDirectory($temporary)|Out-Null
    try{
        $scheme=New-MxhClientScheme $root
        $node=@{name='Fixture-Entry';kind='entry';region_group=$scheme.Layout.region_groups[0];transit_group=$null;clash=@{name='Fixture-Entry';type='vless';server='192.0.2.20';port=443};sing_box=@{tag='Fixture-Entry';type='vless';server='192.0.2.20';server_port=443;tls=@{reality=@{enabled=$true}}}}
        $scheme.Entries=@(@{Id='fixture';Node=$node;Source=@{Kind='Manual'}})
        $hash=Get-MxhSchemeHash $scheme
        Check ($hash -eq (Get-MxhSchemeHash $scheme)) 'spec hash is deterministic'
        $clone=($scheme | ConvertTo-Json -Depth 60)|ConvertFrom-Json -AsHashtable
        Check ($hash -eq (Get-MxhSchemeHash $clone)) 'hash survives save/reload dictionary order changes'
        $clone.Entries[0].Node.sing_box.server_port=444
        Check ($hash -ne (Get-MxhSchemeHash $clone)) 'node changes invalidate candidates'
        $spec=Get-MxhSchemeSpec $scheme
        Check ($spec.manual_nodes.Count -eq 1 -and $spec.groups.Count -gt 3) 'default spec creates groups without prompting'
        $clone=Copy-MxhHashtable $scheme;$clone.Entries+=@($clone.Entries[0])
        Fails {Get-MxhSchemeSpec $clone} 'duplicate nodes rejected'
        $clone=Copy-MxhHashtable $scheme;$clone.Entries[0].Node.kind='landing';$clone.Entries[0].Node.transit_group='Missing'
        Fails {Get-MxhSchemeSpec $clone} 'missing entry relationships rejected'
        $scheme.Name='fixture draft';$scheme.Entries[0].Node.clash.password='test-only-sensitive-value'
        Save-MxhClientScheme $scheme $temporary
        $saved=Join-Path $temporary ('private/client-schemes/'+$scheme.Id+'.private.json')
        Check ((Get-Content -Raw $saved) -notmatch 'test-only-sensitive-value|192\.0\.2\.20') 'saved draft encrypts node data'
        function Read-VpsMenu { return 1 }
        $loaded=Open-MxhClientScheme $temporary
        Check ($loaded.Entries[0].Node.clash.password -eq 'test-only-sensitive-value' -and -not $loaded.Candidate) 'draft decrypts and discards prior validation'
        Remove-Item Function:\Read-VpsMenu
        $sourceClash=Join-Path $temporary 'source.yaml';$sourceSing=Join-Path $temporary 'source.json'
        [IO.File]::WriteAllText($sourceClash,"proxies: []`n")
        Save-VpsJson @{outbounds=@()} $sourceSing
        $targetClash=Join-Path $temporary 'target.yaml';$targetSing=Join-Path $temporary 'target.json'
        [IO.File]::WriteAllText($targetClash,'old clash');[IO.File]::WriteAllText($targetSing,'old sing')
        $backup=Join-Path $temporary 'backups'
        Fails {Publish-MxhAuthorityPair $sourceClash $sourceSing $targetClash $targetClash $backup} 'same target rejected'
        Fails {Publish-MxhAuthorityPair $sourceClash $sourceSing $targetClash $targetSing $backup -Expected @{Clash='changed';SingBox='changed'}} 'changed target rejected'
        Check ((Get-Content -Raw $targetClash) -eq 'old clash') 'rejected publication preserves original'
        $published=Publish-MxhAuthorityPair $sourceClash $sourceSing $targetClash $targetSing $backup -Expected @{Clash=Get-MxhFileFingerprint $targetClash;SingBox=Get-MxhFileFingerprint $targetSing}
        Check ((Get-Content -Raw $targetClash) -eq "proxies: []`n") 'pair publishes candidate'
        Check ((Read-VpsJsonHashtable (Join-Path $backup 'publish.private.json')).Phase -eq 'Committed') 'publication journal committed'
        Check (@(Get-ChildItem $backup -Filter '*.backup').Count -eq 2) 'distinct backup names preserve both files'
        $journalPath=Join-Path $backup 'publish.private.json'
        $interrupted=Read-VpsJsonHashtable $journalPath;$interrupted.Phase='ClashApplied';Save-VpsJson $interrupted $journalPath
        [IO.File]::WriteAllText($targetClash,'external change')
        Fails {Restore-MxhPendingPublication $journalPath} 'recovery refuses unrelated external edits'
        Copy-Item -LiteralPath $sourceClash -Destination $targetClash -Force
        Restore-MxhPendingPublication $journalPath
        Check ((Get-Content -Raw $targetClash) -eq 'old clash' -and (Get-Content -Raw $targetSing) -eq 'old sing') 'interrupted pair recovers both originals'
        $script:baseSave=${function:Save-VpsJson}
        function Save-VpsJson {param($Value,[string]$Path,[switch]$Private)
            if($Value -is [Collections.IDictionary] -and $Value.Contains('Phase') -and $Value.Phase -eq 'ClashApplied'){throw 'Simulated journal write failure after first replacement'}
            & $script:baseSave @PSBoundParameters
        }
        try{Fails {Publish-MxhAuthorityPair $sourceClash $sourceSing $targetClash $targetSing (Join-Path $temporary 'failure')} 'first replacement failure propagates'}finally{Remove-Item Function:\Save-VpsJson;Remove-Variable baseSave -Scope Script}
        Check ((Get-Content -Raw $targetClash) -eq 'old clash' -and (Get-Content -Raw $targetSing) -eq 'old sing') 'first replacement failure restores pair'
        $held=[IO.File]::Open($targetSing+'.may-publish.lock','OpenOrCreate','ReadWrite','None')
        try{Fails {Publish-MxhAuthorityPair $sourceClash $sourceSing $targetClash $targetSing (Join-Path $temporary 'locked')} 'concurrent publisher blocked'}finally{$held.Dispose()}
        function Test-MxhClientAuthorityPair {return @{mihomo=@{Status='Ready'};'sing-box'=@{Status='Ready'}}}
        Invoke-MxhSchemeBuild $scheme $root -OutputRoot (Join-Path $temporary 'candidate')
        Check ([bool]$scheme.Candidate -and [IO.File]::Exists($scheme.Candidate.Clash)) 'workbench spec builds a real candidate using Python engine'
        $inspected=@(Read-MxhSchemeSources $root $scheme.Candidate.Clash $scheme.Candidate.SingBox)
        Check ($inspected.Count -eq 1 -and $inspected[0].name -eq 'Fixture-Entry') 'paired source inspector reads produced node'
        $python=Get-VpsCommandPath 'python.exe'
        $diff=Invoke-VpsProcess $python @((Join-Path $root 'scripts/summarize_client_change.py'),'--old-clash',$targetClash,'--old-sing',$targetSing,'--new-clash',$scheme.Candidate.Clash,'--new-sing',$scheme.Candidate.SingBox)
        Check ($diff.ExitCode -eq 0 -and $diff.StdOut -notmatch 'test-only-sensitive-value|192\.0\.2\.20') 'change summary does not expose credentials or endpoint values'
        $diffValue=$diff.StdOut | ConvertFrom-Json -AsHashtable
        Check ($diffValue.Clash.Added -contains 'Fixture-Entry') 'change summary identifies added node names'
        $script:queue=[Collections.Generic.Queue[string]]::new()
        function Read-Host {param([string]$Prompt);if(-not $script:queue.Count){throw 'Unexpected input prompt'};$script:queue.Dequeue()}
        function Read-MxhSchemeSources {return @(@{name='First';kind='entry';region_group=$null;transit_group=$null;clash=@{name='First'};sing_box=@{tag='First'}},@{name='Second';kind='entry';region_group=$null;transit_group=$null;clash=@{name='Second'};sing_box=@{tag='Second'}})}
        $selectionScheme=New-MxhClientScheme $root;$selectionScheme.Layout.region_groups=@('Only Entry')
        @('3','1')|ForEach-Object {$script:queue.Enqueue($_)}
        Add-MxhSchemeSourceNodes $selectionScheme $root $temporary
        Check ($selectionScheme.Entries.Count -eq 1 -and $selectionScheme.Entries[0].Node.name -eq 'First') 'index selection uses zero-based helper correctly'
        @('1','2','0','0','0')|ForEach-Object {$script:queue.Enqueue($_)}
        $back=$false;try{Edit-MxhSchemeEntry $selectionScheme}catch{if(Test-VpsWizardBackError $_){$back=$true}else{throw}}
        Check ($back -and $script:queue.Count -eq 0) 'node field back visits action menu then node menu'
        @('0','3','0','2')|ForEach-Object {$script:queue.Enqueue($_)}
        Invoke-MxhClientWorkbench $root $temporary $selectionScheme
        Check ($script:queue.Count -eq 0) 'unsaved draft can continue editing then explicitly discard'
        Remove-Item Function:\Read-Host,Function:\Read-MxhSchemeSources
        Remove-Variable queue -Scope Script
        $scheme.Sources[$sourceClash]='obsolete'
        Fails {Invoke-MxhSchemeBuild $scheme $root -OutputRoot (Join-Path $temporary 'changed')} 'changed source blocks build'
        $input=@{Plan=@{Server=@{IPv4='192.0.2.10'};Ports=@{SshPrimary=30001;SshRescue=30002;XrayPrimary=443;XrayBackup=40000;AnyTlsPrimary=$null;LandingShadowsocks=$null};TrustedTls=@{Enabled=$false};Reality=@{XrayVersion='new';Target='new.example'};AnyTls=@{};Shadowsocks=@{};Paths=@{Archive='current'};ProtocolInventory=@{}};State=@{};Secrets=@{}}
        function Get-MxhProtocolInventory {return @{RealityEntry=@{Installed=$true};AnyTlsEntry=@{Installed=$false};ShadowsocksLanding=@{Installed=$false}}}
        $old=Copy-MxhHashtable $input.Plan;$old.Reality.XrayVersion='old';$old.Reality.Target='old.example';$old.Ports.SshPrimary=22
        $restored=New-MxhRestoreMetadata $input $old @{} @{Xray=@{Value='fixture'}} ConfigOnly
        Check ($restored.Plan.Ports.SshPrimary -eq 30001 -and $restored.Plan.Reality.XrayVersion -eq 'new') 'config-only preserves current SSH and runtime metadata'
        Check ($restored.Plan.Reality.Target -eq 'old.example') 'config-only restores protocol configuration'
        $old.Ports.XrayPrimary=8443
        Fails {New-MxhRestoreMetadata $input $old @{} @{Xray=@{}} ConfigOnly} 'config-only rejects firewall incompatible port change'
        Fails {New-MxhRestoreMetadata $input $old @{} @{} Full} 'missing snapshot credentials rejected'
        Write-Host "Workbench tests passed: $script:workbenchChecks assertions" -ForegroundColor Green
    }finally{
        # Only this test's explicit GUID-scoped directory is removed.
        $resolved=[IO.Path]::GetFullPath($temporary)
        if(-not $resolved.StartsWith([IO.Path]::GetFullPath((Join-Path $root '.tmp'))+[IO.Path]::DirectorySeparatorChar)){throw 'Unexpected test cleanup path'}
        Remove-Item -LiteralPath $resolved -Recurse -Force
        Remove-Variable workbenchChecks -Scope Script -ErrorAction SilentlyContinue
    }
} $ProjectRoot
