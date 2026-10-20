function Get-VpsGuiAskPassPath {
    param([Parameter(Mandatory)][string]$ProjectRoot)
    $bundled=Join-Path $ProjectRoot 'app-helpers/AskPass.exe'
    if(Test-Path -LiteralPath (Join-Path $ProjectRoot 'desktop-runtime.json')){
        $runtime=Get-Content -Raw -LiteralPath (Join-Path $ProjectRoot 'desktop-runtime.json')|ConvertFrom-Json -AsHashtable
        $entry=@($runtime.files|Where-Object path -CEQ 'app-helpers/AskPass.exe')
        if($entry.Count -ne 1 -or -not(Test-Path -LiteralPath $bundled) -or (Get-FileHash -LiteralPath $bundled).Hash.ToLowerInvariant() -ne $entry[0].sha256){throw '内置 SSH 图形认证辅助程序校验失败。'}
        return $bundled
    }
    $source=Join-Path $ProjectRoot 'src/gui/VpsDeploy.AskPass.cs'
    $directory=Join-Path $ProjectRoot '.cache/gui-ssh'
    if ((Test-Path $directory) -and ((Get-Item -LiteralPath $directory -Force).Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw 'SSH 图形认证缓存目录不能是联接。' }
    [IO.Directory]::CreateDirectory($directory)|Out-Null
    $executable=Join-Path $directory 'askpass.exe';$stamp=Join-Path $directory 'helper-sha256.json'
    $hash=(Get-FileHash -LiteralPath $source).Hash
    if ((Test-Path $executable) -and (Test-Path $stamp)) {
        $saved=Get-Content -Raw -LiteralPath $stamp|ConvertFrom-Json -AsHashtable
        if($saved.source -eq $hash -and $saved.executable -eq (Get-FileHash -LiteralPath $executable).Hash){return $executable}
    }
    $compiler=Join-Path $env:WINDIR 'Microsoft.NET/Framework64/v4.0.30319/csc.exe'
    if(-not(Test-Path -LiteralPath $compiler -PathType Leaf)){throw '缺少 Windows .NET Framework 编译器，无法使用图形 SSH 认证。'}
    $temporary=Join-Path $directory ('askpass-'+[guid]::NewGuid().ToString('N')+'.exe')
    try {
        $result=Invoke-VpsProcess $compiler @('/nologo','/target:exe','/optimize+',"/out:$temporary",$source)
        if($result.ExitCode -ne 0){throw 'SSH 图形认证辅助程序编译失败。'}
        [IO.File]::Move($temporary,$executable,$true)
        Save-VpsJson @{source=$hash;executable=(Get-FileHash -LiteralPath $executable).Hash} $stamp
        return $executable
    } finally {if(Test-Path -LiteralPath $temporary){Remove-Item -LiteralPath $temporary}}
}
function Invoke-VpsGuiSshAuthentication {
    param([Parameter(Mandatory)]$Context,[Parameter(Mandatory)][string]$FilePath,[string[]]$ArgumentList)
    $helper=Get-VpsGuiAskPassPath $Context.ProjectRoot
    $broker=[May.VpsDeploy.Gui.SshSecretBroker]::new($script:VpsInteractionSession)
    $start=[Diagnostics.ProcessStartInfo]::new($FilePath)
    $start.UseShellExecute=$false;$start.CreateNoWindow=$true
    $start.RedirectStandardInput=$true;$start.RedirectStandardOutput=$true;$start.RedirectStandardError=$true
    $start.Environment['SSH_ASKPASS']=$helper;$start.Environment['SSH_ASKPASS_REQUIRE']='force'
    $start.Environment['DISPLAY']='mxh-vps-deploy';$start.Environment['MXH_VPS_GUI_ASKPASS_PIPE']=$broker.PipeName
    foreach($argument in $ArgumentList){$start.ArgumentList.Add($argument)}
    $process=$null
    try {
        $process=[Diagnostics.Process]::Start($start);$process.StandardInput.Close()
        $output=$process.StandardOutput.ReadToEndAsync();$errors=$process.StandardError.ReadToEndAsync()
        if(-not $process.WaitForExit(180000)){$process.Kill($true);throw 'SSH 图形认证超时；旧入口保留。'}
        return [pscustomobject]@{ExitCode=$process.ExitCode;StdOut=$output.GetAwaiter().GetResult();StdErr=$errors.GetAwaiter().GetResult()}
    } finally {if($process){$process.Dispose()};$broker.Dispose()}
}
