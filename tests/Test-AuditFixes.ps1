[CmdletBinding()]
param([Parameter(Mandatory)][string]$ProjectRoot)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
Import-Module (Join-Path $ProjectRoot 'src/VpsDeploy.Core.psm1') -Force
$module=Get-Module VpsDeploy.Core
& $module {
    param($root)
    $script:auditChecks=0
    function Check($value,$message){if(-not $value){throw "Audit regression: $message"};$script:auditChecks++}
    function Fails([scriptblock]$action,$message){$failed=$false;try{& $action|Out-Null}catch{$failed=$true};Check $failed $message}
    $work=Join-Path $root ('.tmp/audit-fixes-'+[Guid]::NewGuid().ToString('N'))
    [IO.Directory]::CreateDirectory($work)|Out-Null
    try {
        # The fresh baseline guard is absent from completed maintenance payloads.
        $payloadContext=[pscustomobject]@{ProjectRoot=$root;State=@{DeploymentTransaction=@{Status='Armed';RemoteBaselineDirectory='/root/vps-deploy-transaction-baselines/'+'a'*32}}}
        $payload=New-VpsRemoteScriptPayload $payloadContext 'nftables-apply.sh' @{TCP_PORTS='22,443'}
        Check ($payload.Contains('export VPS_PARAM_DEPLOYMENT_BASELINE=') -and -not $payload.Contains("`r")) 'fresh deployment uses owned firewall baseline with LF payload'
        $payloadContext.State.DeploymentTransaction.Status='Committed'
        $payload=New-VpsRemoteScriptPayload $payloadContext 'nftables-apply.sh' @{TCP_PORTS='22,443'}
        Check (-not $payload.Contains('export VPS_PARAM_DEPLOYMENT_BASELINE=')) 'completed deployment baseline is not reused by maintenance'
        $payload=New-VpsRemoteScriptPayload $payloadContext 'maintenance-ssh-apply.sh' @{FIREWALL_REQUIRED='false'}
        Check ($payload.Contains('mxh_firewall()')) 'CLI SSH payload includes the shared firewall helper'
        # Rotation preserves advanced routing, ports, source binding and unmodified secret fields.
        $old=@{Shadowsocks=@{ServerKey='fixture-server';PrimaryUserKey='fixture-old4';SecondaryUserKey='fixture-old6'}}
        $new=@{Shadowsocks=@{ServerKey='fixture-server';PrimaryUserKey='fixture-new4';SecondaryUserKey='fixture-new6'}}
        $config=@{dns=@{servers=@(@{type='local';tag='local'})};inbounds=@(@{type='shadowsocks';listen_port=33456;password='fixture-server';users=@(@{name='ipv4-client';password='fixture-old4'},@{name='ipv6-client';password='fixture-old6'})});outbounds=@(@{type='direct';tag='v6';inet6_bind_address='2001:db8::20';bind_interface='eth0'});route=@{rules=@(@{auth_user=@('ipv6-client');action='route';outbound='v6'})}}
        $rotated=New-MxhRotatedProtocolConfig $config $old $new ShadowsocksLanding
        Check ($rotated.inbounds[0].users[0].password -eq 'fixture-new4' -and $rotated.inbounds[0].users[1].password -eq 'fixture-new6') 'both SS user keys rotate'
        Check ($rotated.outbounds[0].inet6_bind_address -eq '2001:db8::20' -and $rotated.outbounds[0].bind_interface -eq 'eth0') 'IPv6 source/interface retained'
        Check (($rotated.route|ConvertTo-Json -Depth 20 -Compress) -eq ($config.route|ConvertTo-Json -Depth 20 -Compress)) 'custom route retained'
        Check ($config.inbounds[0].users[0].password -eq 'fixture-old4' -and $rotated.inbounds[0].listen_port -eq 33456) 'original and port preserved'
        $config.inbounds[0].users+=@(@{name='unmanaged';password='fixture-extra'})
        Fails {New-MxhRotatedProtocolConfig $config $old $new ShadowsocksLanding} 'unmanaged SS users rejected'
        $reality=@{inbounds=@(@{protocol='vless';settings=@{clients=@(@{id='fixture-old'})};streamSettings=@{security='reality';realitySettings=@{privateKey='fixture-private';shortIds=@('aa','bb')}}});routing=@{domainStrategy='AsIs'}}
        $updated=New-MxhRotatedProtocolConfig $reality @{Xray=@{Uuid='fixture-old';RealityPrivateKey='fixture-private';ShortId='aa'}} @{Xray=@{Uuid='fixture-new';RealityPrivateKey='fixture-new-key';ShortId='cc'}} RealityEntry
        Check (($updated.inbounds[0].streamSettings.realitySettings.shortIds -join ',') -eq 'cc,bb') 'only managed Reality shortId changes'
        Check ($updated.routing.domainStrategy -eq 'AsIs') 'Reality routing retained'

        # Health classification needs listener/certificate evidence, not just active units.
        $inventory=@{RealityEntry=@{Installed=$false;Enabled=$false;Active=$false};AnyTlsEntry=@{Installed=$false;Enabled=$false;Active=$false};ShadowsocksLanding=@{Installed=$true;Enabled=$true;Active=$true}}
        $plan=@{Server=@{IPv4='192.0.2.20'};ProtocolInventory=$inventory;Ports=@{SshPrimary=30123;SshRescue=31234;LandingShadowsocks=33456;AnyTlsPrimary=443};Shadowsocks=@{SingBoxVersion='1.14.2'};AnyTls=@{SingBoxVersion='1.14.2'};Reality=@{TargetMode='ExternalAudited'};Komari=@{Enabled=$false}}
        $health=[pscustomobject]@{Plan=$plan;State=@{Modules=@{};KomariInstalled=$false};Secrets=@{};DryRun=$false}
        $audit=@{CollectedAt='fixture';Ssh=@{Valid=$true;Ports=@(30123,31234);PasswordAuthentication='no';KbdInteractiveAuthentication='no';PubkeyAuthentication='yes'};Listeners=@{Tcp=@(30123,31234,33456,443);Udp=@(33456)};Services=Copy-MxhHashtable $inventory;Versions=@{Xray=$null;SingBoxAnyTls='sing-box version 1.14.2';SingBox='sing-box version 1.14.2';KomariAgent=$null;KomariController=$null};Hashes=@{};Nftables=@{Present=$true;Valid=$true};Certificates=@{AnyTls=@{Present=$true;DaysRemaining=90};Reality=@{Present=$true;DaysRemaining=90}};Timers=@{RollbackActive=$false;CertbotRenewEnabled=$true;CertbotRenewActive=$true};ChecksIncomplete=@()}
        foreach($role in @('KomariAgent','KomariController','Cloudflared')){$audit.Services[$role]=@{Installed=$false;Enabled=$false;Active=$false;ProcessMatchesBinary=$null}}
        function Invoke-VpsRemoteScript {return [pscustomobject]@{StdOut=('VPSDEPLOY_HEALTH_AUDIT_B64='+[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes(($audit|ConvertTo-Json -Compress -Depth 25))))}}
        Check ((Get-MxhHealthAudit $health).Status -eq 'Healthy') 'complete evidence is healthy'
        $audit.Listeners.Udp=@()
        Check ('REQUIRED_LISTENER_MISSING' -in (Get-MxhHealthAudit $health).Findings.Code) 'missing UDP is detected despite active SS unit'
        $audit.Listeners.Udp=@(33456);$audit.Services.ShadowsocksLanding.ProcessMatchesBinary=$false
        Check ('RUNNING_BINARY_MISMATCH' -in (Get-MxhHealthAudit $health).Findings.Code) 'stale running binary is detected'
        $audit.Services.ShadowsocksLanding.ProcessMatchesBinary=$true;$audit.ChecksIncomplete=@('sshd')
        Check ((Get-MxhHealthAudit $health).Status -eq 'Warning') 'partial audit cannot be healthy'
        $audit.ChecksIncomplete=@();$plan.ProtocolInventory.AnyTlsEntry=@{Installed=$true;Enabled=$true;Active=$true};$plan.ProtocolInventory.ShadowsocksLanding=@{Installed=$false;Enabled=$false;Active=$false}
        $audit.Services.AnyTlsEntry=Copy-MxhHashtable $plan.ProtocolInventory.AnyTlsEntry;$audit.Services.ShadowsocksLanding=Copy-MxhHashtable $plan.ProtocolInventory.ShadowsocksLanding
        $audit.Certificates.AnyTls.DaysRemaining=-1
        Check ('TLS_CERT_INVALID' -in (Get-MxhHealthAudit $health).Findings.Code) 'expired AnyTLS certificate is critical'
        $audit.Certificates.AnyTls.DaysRemaining=90;$audit.Timers.CertbotRenewActive=$false
        Check ('CERTBOT_RENEW_UNAVAILABLE' -in (Get-MxhHealthAudit $health).Findings.Code) 'inactive renewal timer is detected'
        Remove-Item Function:\Invoke-VpsRemoteScript
        $health.Plan.Komari.Enabled=$true;$health.State.KomariInstalled=$true;$health.State.KomariController=@{Installed=$true;Active=$true;Enabled=$true};$health.Secrets=@{Komari=@{Token='fixture-current'};AnyTls=@{Password='fixture-current-password'}}
        $savedPlan=Copy-MxhHashtable $health.Plan;$savedPlan.Komari.Enabled=$false
        $savedState=@{KomariInstalled=$false;KomariController=@{Installed=$false;Enabled=$false;Active=$false}}
        $restored=New-MxhRestoreMetadata $health $savedPlan $savedState @{Komari=@{Token='fixture-old'};AnyTls=@{Password='fixture-restored'}} Full
        Check ($restored.Plan.Komari.Enabled -and $restored.State.KomariInstalled -and $restored.State.KomariController.Active) 'protocol full restore retains current monitoring metadata'
        Check ($restored.Secrets.Komari.Token -eq 'fixture-current' -and $restored.Secrets.AnyTls.Password -eq 'fixture-restored') 'protocol restore does not replace current monitor credentials'

        # Both formal authority entry points use the same Ready and fingerprint gate.
        $ca=Join-Path $work 'candidate.yaml';$cs=Join-Path $work 'candidate.json';$ta=Join-Path $work 'authority.yaml';$ts=Join-Path $work 'authority.json'
        [IO.File]::WriteAllText($ca,'candidate-a');[IO.File]::WriteAllText($cs,'candidate-s');[IO.File]::WriteAllText($ta,'old-a');[IO.File]::WriteAllText($ts,'old-s')
        $params=@{CandidateClash=$ca;CandidateSingBox=$cs;TargetClash=$ta;TargetSingBox=$ts;BackupRoot=(Join-Path $work 'publish-backup');Expected=@{Clash=Get-MxhFileFingerprint $ta;SingBox=Get-MxhFileFingerprint $ts};ExpectedCandidates=@{Clash=Get-MxhFileFingerprint $ca;SingBox=Get-MxhFileFingerprint $cs};Sources=@{};States=@{mihomo=@{Status='Ready'};'sing-box'=@{Status='SkippedByUser'}}}
        Fails {Publish-MxhCheckedAuthorityPair @params} 'skipped validation cannot publish'
        Check ((Get-Content -Raw $ta) -eq 'old-a' -and (Get-Content -Raw $ts) -eq 'old-s') 'rejected publish leaves both targets unchanged'
        $params.States['sing-box'].Status='Ready';$params.Sources[$ca]=Get-MxhFileFingerprint $ca
        [IO.File]::WriteAllText($ca,'changed candidate')
        Fails {Publish-MxhCheckedAuthorityPair @params} 'changed source cannot publish'
        $params.Sources=@{}
        Fails {Publish-MxhCheckedAuthorityPair @params} 'changed validated candidate cannot publish'
        $params.ExpectedCandidates.Clash=Get-MxhFileFingerprint $ca
        Publish-MxhCheckedAuthorityPair @params|Out-Null
        Check ((Get-Content -Raw $ts) -eq 'candidate-s') 'checked pair can publish'

        # Legacy fragment descriptors must fingerprint real files, not dictionary names.
        $fragmentDir=Join-Path $work 'fragments';[IO.Directory]::CreateDirectory((Join-Path $fragmentDir 'nested'))|Out-Null
        $fragmentPath=Join-Path $fragmentDir 'nested/node.json';[IO.File]::WriteAllText($fragmentPath,'fixture-node')
        $fragmentSource=[ordered]@{fragment_dir=$fragmentDir;role='RealityEntry';node_names=@('fixture')}
        $sourceFingerprints=Get-MxhClientSourceFingerprints -BasePaths @($ca,$cs) -FragmentSources @($fragmentSource)
        Check ($sourceFingerprints.Count -eq 3 -and $sourceFingerprints.ContainsKey($fragmentPath)) 'fragment_dir descriptors include nested source files'
        $params.Sources=$sourceFingerprints
        $beforePublishA=Get-Content -Raw $ta;$beforePublishS=Get-Content -Raw $ts
        [IO.File]::WriteAllText($fragmentPath,'changed-node')
        Fails {Publish-MxhCheckedAuthorityPair @params} 'fragment mutation after candidate generation prevents publication'
        Check ((Get-Content -Raw $ta) -eq $beforePublishA -and (Get-Content -Raw $ts) -eq $beforePublishS) 'fragment drift leaves both authority targets untouched'
        Fails {Get-MxhClientSourceFingerprints -BasePaths @($ca,$cs) -FragmentSources @(@{role='RealityEntry'})} 'fragment descriptors without a directory are rejected'
        Check ((Get-Command Invoke-MxhBuildClientAuthority).ScriptBlock.ToString().Contains('Get-MxhClientSourceFingerprints -BasePaths')) 'legacy entry invokes the fragment-aware source gate'

        # Generic Komari update really executes the common migration/state flow.
        $script:upgradeCalls=[Collections.Generic.List[object]]::new();$script:verifyCount=0;$script:commits=0;$script:undos=0
        function Get-MxhProtocolInventory {return @{RealityEntry=@{Installed=$false};AnyTlsEntry=@{Installed=$false};ShadowsocksLanding=@{Installed=$false}}}
        function Read-VpsMenu {return 1}
        function Read-VpsYesNo {return $true}
        function Start-MxhMaintenanceTransaction {param($Context,$Label,$Components,[switch]$QuiesceKomariController);$script:upgradeCalls.Add(@{Action='Arm';Components=$Components;Quiesced=[bool]$QuiesceKomariController})}
        function Invoke-VpsScpDownload {param($Context,$Remote,$Local);[IO.File]::WriteAllText($Local,'fixture-backup')}
        function Complete-MxhMaintenanceTransaction {$script:commits++}
        function Save-MxhMaintenanceContext {}
        function Undo-MxhMaintenanceTransaction {$script:undos++}
        function Get-MxhHealthAudit {return @{Status='Healthy'}}
        function Invoke-VpsRemoteScript {
            param($Context,$Asset,$Parameters,$TimeoutSeconds)
            $script:upgradeCalls.Add($Parameters.Clone())
            $output=switch($Parameters.ACTION){
                'ControllerBackup' {'VPSDEPLOY_KOMARI_BACKUP_B64='+[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes('/root/komari-controller-20261001-000000.tar.gz'))}
                'ControllerUpgrade' {Check ($Parameters.ContainsKey('BACKUP_FILE')) 'generic Controller passes backup file';'VPSDEPLOY_KOMARI_LIFECYCLE_OK'+"`nVPSDEPLOY_KOMARI_MIGRATION_REQUIRED_B64=dHJ1ZQ=="}
                'ControllerVerify' {$script:verifyCount++;'VPSDEPLOY_KOMARI_MIGRATION_REQUIRED_B64=ZmFsc2U='}
                'Status' {"komari-agent.service=true,true,true`nkomari.service=true,true,true`ncloudflared.service=true,false,false`n"}
                default {'VPSDEPLOY_KOMARI_LIFECYCLE_OK'}
            }
            [pscustomobject]@{StdOut=$output}
        }
        $context=[pscustomobject]@{ProjectRoot=$root;ArchivePath=$work;Plan=@{Komari=@{Enabled=$false}};State=@{Audit=@{Architecture='x86_64'};KomariInstalled=$false;KomariController=@{Installed=$true}};Versions=(Get-VpsVersions $root);DryRun=$false}
        Invoke-MxhControlledUpgrade $context
        Check ($script:verifyCount -eq 1 -and $script:commits -eq 1 -and $script:undos -eq 0) 'migration pending must be reverifed before commit'
        Check ($script:upgradeCalls[1].Components -eq 'KomariController' -and $script:upgradeCalls[1].Quiesced) 'Controller snapshot is scoped and quiesced'
        Check ($context.Plan.Komari.ControllerVersion -eq '1.5.1' -and $context.State.KomariController.Active) 'Controller version and actual state synchronized'
        Invoke-MxhKomariUpgrade $context KomariAgent
        Check ($context.Plan.Komari.AgentVersion -eq '1.5.11' -and $context.State.KomariInstalled -and $context.Plan.Komari.Enabled) 'Agent metadata synchronized'
        Check (-not $context.State.Cloudflared.Enabled -and -not $context.State.Cloudflared.Active) 'Tunnel actual disabled state retained'
        $script:protocolStatus='SkippedByUser';$script:upgradeMessages=[Collections.Generic.List[object]]::new()
        function Get-MxhProtocolInventory {return @{RealityEntry=@{Installed=$false;Enabled=$false};AnyTlsEntry=@{Installed=$false;Enabled=$false};ShadowsocksLanding=@{Installed=$true;Enabled=$true;Active=$true}}}
        function Invoke-VpsRemoteScript {return [pscustomobject]@{StdOut='VPSDEPLOY_PROTOCOL_STATE_APPLIED'}}
        function Invoke-MxhShadowsocksRealValidation {return @{Status=$script:protocolStatus}}
        function Invoke-MxhShadowsocksExternalValidation {return @{Status='Passed'}}
        function Write-VpsUi {param($Message,$Kind);$script:upgradeMessages.Add(@{Message=$Message;Kind=$Kind})}
        $context.State.KomariInstalled=$false;$context.State.KomariController.Installed=$false
        $context.Plan.Shadowsocks=@{SecondaryBindInterface=$false}
        Invoke-MxhControlledUpgrade $context
        Check ($context.State.LastControlledUpgrade.ValidationStatus -eq 'Incomplete') 'incomplete protocol upgrade acceptance is not recorded as passed'
        Check (@($script:upgradeMessages|Where-Object Kind -eq 'Warning').Count -eq 1) 'incomplete upgrade acceptance is visibly warned'
        $script:protocolStatus='Passed';$script:upgradeMessages.Clear()
        Invoke-MxhControlledUpgrade $context
        Check ($context.State.LastControlledUpgrade.ValidationStatus -eq 'Passed' -and @($script:upgradeMessages|Where-Object Kind -eq 'Success').Count -eq 1) 'fully verified protocol upgrade records success'
        foreach($name in @('Get-MxhProtocolInventory','Read-VpsMenu','Read-VpsYesNo','Start-MxhMaintenanceTransaction','Invoke-VpsScpDownload','Complete-MxhMaintenanceTransaction','Save-MxhMaintenanceContext','Undo-MxhMaintenanceTransaction','Get-MxhHealthAudit','Invoke-VpsRemoteScript','Invoke-MxhShadowsocksRealValidation','Invoke-MxhShadowsocksExternalValidation','Write-VpsUi')){Remove-Item ("Function:\"+$name)}

        # The actual Controller restore UI arms only the components found in its archive.
        function New-FixtureControllerBackup($Path,[switch]$Tunnel,[switch]$Incomplete){
            Add-Type -AssemblyName System.Formats.Tar
            $stream=[IO.File]::Create($Path)
            $gzip=[IO.Compression.GZipStream]::new($stream,[IO.Compression.CompressionMode]::Compress)
            $writer=[System.Formats.Tar.TarWriter]::new($gzip,$true)
            try{
                $names=@('opt/komari/data/komari.db')
                if($Tunnel){$names+='usr/local/bin/cloudflared';if(-not $Incomplete){$names+='etc/systemd/system/cloudflared.service'}}
                foreach($name in $names){
                    $entry=[System.Formats.Tar.PaxTarEntry]::new([System.Formats.Tar.TarEntryType]::RegularFile,$name)
                    $data=[IO.MemoryStream]::new([Text.Encoding]::UTF8.GetBytes('fixture'))
                    try{$entry.DataStream=$data;$writer.WriteEntry($entry)}finally{$data.Dispose()}
                }
            }finally{$writer.Dispose();$gzip.Dispose();$stream.Dispose()}
        }
        $controllerOnly=Join-Path $work 'komari-controller-20261001-010101.tar.gz'
        $controllerFull=Join-Path $work 'komari-controller-20261001-010102.tar.gz'
        $controllerPartial=Join-Path $work 'komari-controller-20261001-010103.tar.gz'
        New-FixtureControllerBackup $controllerOnly;New-FixtureControllerBackup $controllerFull -Tunnel;New-FixtureControllerBackup $controllerPartial -Tunnel -Incomplete
        Check ((@(Get-MxhKomariBackupComponents $controllerOnly) -join ',') -eq 'KomariController') 'controller-only archive excludes tunnel scope'
        Check ((@(Get-MxhKomariBackupComponents $controllerFull) -join ',') -eq 'KomariController,Cloudflared') 'full archive includes tunnel scope'
        Fails {Get-MxhKomariBackupComponents $controllerPartial} 'partial tunnel archive is rejected locally'
        $script:restoreArms=[Collections.Generic.List[object]]::new();$script:restoreChosenFile=$controllerOnly
        function Read-VpsMenu {return 6}
        function Read-VpsText {return $script:restoreChosenFile}
        function Read-VpsYesNo {return $false}
        function Write-VpsUi {}
        function Invoke-VpsScpUpload {}
        function Start-MxhMaintenanceTransaction {param($Context,$Label,$Components,[switch]$QuiesceKomariController);$script:restoreArms.Add(@{Components=$Components;Quiesced=[bool]$QuiesceKomariController})}
        function Complete-MxhMaintenanceTransaction {}
        function Save-MxhMaintenanceContext {}
        function Invoke-VpsRemoteScript {param($Context,$Asset,$Parameters);return @{StdOut=$(if($Parameters.ACTION -eq 'Status'){"komari-agent.service=false,false,false`nkomari.service=true,false,false`ncloudflared.service=true,true,true"}else{"VPSDEPLOY_KOMARI_LIFECYCLE_OK`nVPSDEPLOY_KOMARI_RESTORED_VERSION_B64=MS40LjM="})}}
        $restoreContext=[pscustomobject]@{DryRun=$false;Plan=@{Komari=@{Enabled=$false}};State=@{KomariInstalled=$false}}
        Invoke-MxhKomariLifecycle $restoreContext
        Check (($script:restoreArms[0].Components -join ',') -eq 'KomariController' -and $script:restoreArms[0].Quiesced) 'UI controller-only restore and outer rollback exclude the tunnel'
        $script:restoreChosenFile=$controllerFull;Invoke-MxhKomariLifecycle $restoreContext
        Check (($script:restoreArms[1].Components -join ',') -eq 'KomariController,Cloudflared') 'UI full restore protects both components'
        foreach($name in @('Read-VpsMenu','Read-VpsText','Read-VpsYesNo','Write-VpsUi','Invoke-VpsScpUpload','Start-MxhMaintenanceTransaction','Complete-MxhMaintenanceTransaction','Save-MxhMaintenanceContext','Invoke-VpsRemoteScript')){Remove-Item ("Function:\"+$name)}

        # A download failure after arming decommission must immediately undo the transaction.
        $script:decommissionUndo=0;$script:decommissionCommit=0;$script:decommissionWrites=0;$script:decommissionDownloadFails=$true
        function Read-VpsMenu {return 3}
        function Read-VpsText {return 'DECOMMISSION'}
        function Get-MxhHealthAudit {return @{Status='Healthy'}}
        function Show-MxhHealthAudit {}
        function Get-MxhClientLayoutTemplate {return @{Value=@{authority_defaults=@{clash=(Join-Path $work 'absent.yaml');sing_box=(Join-Path $work 'absent.json')}}}}
        function Start-MxhMaintenanceTransaction {param($Context,$Label,$Components,[switch]$QuiesceKomariController);Check ('KomariController' -notin $Components -and 'Cloudflared' -notin $Components) 'decommission preserving the panel excludes controller and tunnel';return @{RemoteBackup='/root/fixture-backup'}}
        function Invoke-VpsScpDownload {param($Context,$Remote,$Local);if($script:decommissionDownloadFails){throw 'fixture download failed'};[IO.File]::WriteAllText($Local,'fixture archive')}
        function Undo-MxhMaintenanceTransaction {$script:decommissionUndo++}
        function Complete-MxhMaintenanceTransaction {$script:decommissionCommit++}
        function Invoke-VpsRemoteScript {$script:decommissionWrites++;return @{StdOut='VPSDEPLOY_DECOMMISSION_OK'}}
        function Test-VpsSshConnection {return $true}
        function Save-MxhMaintenanceContext {}
        function Write-VpsUi {}
        $decommissionInventory=@{};foreach($role in Get-MxhManagedProtocolRoles){$decommissionInventory[$role]=@{Installed=$false;Enabled=$false;Active=$false}}
        $decommissionContext=[pscustomobject]@{ProjectRoot=$root;ArchivePath=$work;DryRun=$false;State=@{KomariInstalled=$false};Plan=@{NodeName='fixture';Role='MonitorOnly';ProtocolInventory=$decommissionInventory;Komari=@{Enabled=$false};Firewall=@{Mode='PreserveExisting'};Ports=@{SshPrimary=30123;SshRescue=31234}}}
        Fails {Invoke-MxhDecommission $decommissionContext} 'decommission snapshot download failure surfaces'
        Check ($script:decommissionUndo -eq 1 -and $script:decommissionCommit -eq 0 -and $script:decommissionWrites -eq 0) 'post-arm download failure is undone before any destructive remote operation'
        $script:decommissionDownloadFails=$false
        Invoke-MxhDecommission $decommissionContext
        Check ($script:decommissionCommit -eq 1 -and $script:decommissionWrites -eq 1) 'monitor-only decommission completes with a downloaded snapshot'
        foreach($name in @('Read-VpsMenu','Read-VpsText','Get-MxhHealthAudit','Show-MxhHealthAudit','Get-MxhClientLayoutTemplate','Start-MxhMaintenanceTransaction','Invoke-VpsScpDownload','Undo-MxhMaintenanceTransaction','Complete-MxhMaintenanceTransaction','Invoke-VpsRemoteScript','Test-VpsSshConnection','Save-MxhMaintenanceContext','Write-VpsUi')){Remove-Item ("Function:\"+$name)}

        # Verified executable cache repairs tampering instead of trusting only the ZIP marker.
        $mini=Join-Path $work 'asset-project';[IO.Directory]::CreateDirectory((Join-Path $mini 'config'))|Out-Null
        Copy-Item -LiteralPath (Join-Path $root 'config/versions.json') -Destination (Join-Path $mini 'config/versions.json')
        Copy-Item -LiteralPath (Join-Path $root 'vendor') -Destination (Join-Path $mini 'vendor') -Recurse
        $core=Get-VpsBundledClientCore $mini sing-box;$original=(Get-FileHash -LiteralPath $core).Hash
        [IO.File]::WriteAllText($core,'tampered fixture')
        $repaired=Get-VpsBundledClientCore $mini sing-box
        Check ((Get-FileHash -LiteralPath $repaired).Hash -eq $original) 'cache executable tampering is repaired'
        $sentinel=Join-Path (Split-Path -Parent $core) 'fixture-marker.txt';[IO.File]::WriteAllText($sentinel,'remove on explicit rebuild')
        Get-VpsBundledClientCore $mini sing-box -ForceRebuild|Out-Null
        Check (-not(Test-Path -LiteralPath $sentinel)) 'explicit retry rebuilds the cache'
        $vendor=Join-Path $mini 'vendor/test-cores/windows-amd64'
        $geo=Join-Path $vendor 'mihomo-geodata/GeoIP.dat';Remove-Item -LiteralPath $geo
        & (Join-Path $root 'scripts/Sync-ClientValidationAssets.ps1') -ProjectRoot $mini -SourceDirectory (Join-Path $root 'vendor/test-cores/windows-amd64') -Offline
        Check (Test-Path -LiteralPath $geo) 'missing GeoData rebuilt entirely offline'
        [IO.File]::WriteAllText($geo,'damaged fixture')
        Fails {& (Join-Path $root 'scripts/Sync-ClientValidationAssets.ps1') -ProjectRoot $mini -SourceDirectory (Join-Path $root 'vendor/test-cores/windows-amd64') -Offline} 'mismatched GeoData requires explicit repair'
        & (Join-Path $root 'scripts/Sync-ClientValidationAssets.ps1') -ProjectRoot $mini -SourceDirectory (Join-Path $root 'vendor/test-cores/windows-amd64') -Offline -RepairExisting
        Check ((Get-FileHash -LiteralPath $geo).Hash -eq (Get-FileHash -LiteralPath (Join-Path $root 'vendor/test-cores/windows-amd64/mihomo-geodata/GeoIP.dat')).Hash) 'explicit repair restores pinned bytes'
        & (Join-Path $root 'scripts/Sync-ClientValidationAssets.ps1') -ProjectRoot $mini -Offline
        Check $true 'complete verified assets require no network'

        # ignored local private files pass; public/staged secrets fail without showing their values.
        $repo=Join-Path $work 'secret-fixture';[IO.Directory]::CreateDirectory((Join-Path $repo 'private'))|Out-Null
        [IO.File]::WriteAllText((Join-Path $repo '.gitignore'),"private/`n")
        [IO.File]::WriteAllText((Join-Path $repo 'private/generated.private.json'),('{"fixture":"'+[Guid]::NewGuid().ToString()+'"}'))
        & git -C $repo init -q
        if($LASTEXITCODE -ne 0){throw 'fixture git init failed'}
        & (Join-Path $root 'scripts/Test-NoSecrets.ps1') -ProjectRoot $repo
        Check $true 'ignored local runtime secrets are not treated as public files'
        & git -c core.excludesFile= -C $repo add -f -- private/generated.private.json
        if($LASTEXITCODE -ne 0){throw 'fixture git add failed'}
        Fails {& (Join-Path $root 'scripts/Test-NoSecrets.ps1') -ProjectRoot $repo} 'staged private archive is rejected'
        $zip=Join-Path $work 'source-zip';[IO.Directory]::CreateDirectory((Join-Path $zip 'private'))|Out-Null
        [IO.File]::WriteAllText((Join-Path $zip 'private/runtime.private.json'),'fixture')
        & (Join-Path $root 'scripts/Test-NoSecrets.ps1') -ProjectRoot $zip
        Check $true 'source ZIP recognizes runtime data boundary'
        $pickerRelative='desktop/May.VpsDeploy.Windows/WindowsSavePathPicker.cs'
        $picker=Join-Path $zip $pickerRelative;[IO.Directory]::CreateDirectory((Split-Path -Parent $picker))|Out-Null
        $pickerSource=Get-Content -Raw -LiteralPath (Join-Path $root $pickerRelative)
        [IO.File]::WriteAllText($picker,$pickerSource)
        & (Join-Path $root 'scripts/Test-NoSecrets.ps1') -ProjectRoot $zip
        Check $true 'exact public Shell COM declarations are recognized'
        [IO.File]::AppendAllText($picker,('[Guid("'+[Guid]::NewGuid().ToString()+'")]'))
        Fails {& (Join-Path $root 'scripts/Test-NoSecrets.ps1') -ProjectRoot $zip} 'other UUIDs in the same adapter still fail'
        [IO.File]::WriteAllText($picker,$pickerSource)
        $elsewhere=Join-Path $zip 'public-copy.cs';[IO.File]::WriteAllText($elsewhere,$pickerSource)
        Fails {& (Join-Path $root 'scripts/Test-NoSecrets.ps1') -ProjectRoot $zip} 'public COM UUID exemption is limited to exact adapter path'
        [IO.File]::Delete($elsewhere)
        [IO.File]::WriteAllText((Join-Path $zip 'root.txt'),'fixture')
        Fails {& (Join-Path $root 'scripts/Test-NoSecrets.ps1') -ProjectRoot $zip} 'source ZIP cannot hide root credentials in public root'
    }finally{
        if(Test-Path -LiteralPath $work){
            $resolved=[IO.Path]::GetFullPath($work);$boundary=[IO.Path]::GetFullPath((Join-Path $root '.tmp'))+[IO.Path]::DirectorySeparatorChar
            if(-not $resolved.StartsWith($boundary,[StringComparison]::OrdinalIgnoreCase)){throw 'fixture cleanup path escaped .tmp'}
            Remove-Item -LiteralPath $resolved -Recurse -Force
        }
    }
    Write-Host "Audit behavior tests passed: $script:auditChecks assertions" -ForegroundColor Green
} $ProjectRoot
