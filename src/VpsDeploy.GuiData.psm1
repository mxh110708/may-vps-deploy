#requires -Version 7.4
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
function Get-VpsGuiDataPaths {
    param([Parameter(Mandatory)][string]$ProjectRoot)
    $root = [IO.Path]::GetFullPath((Join-Path $ProjectRoot 'private'))
    foreach($directory in @($root,(Join-Path $root 'instances'))){
        if((Test-Path -LiteralPath $directory) -and ((Get-Item -LiteralPath $directory -Force).Attributes -band [IO.FileAttributes]::ReparsePoint)){throw '应用私人数据目录不能使用外部联接。'}
    }
    return @{ Root=$root; Instances=(Join-Path $root 'instances'); Settings=(Join-Path $root 'gui-settings.json'); History=(Join-Path $root 'task-history.json') }
}
function Test-VpsGuiPlanPath {
    param([Parameter(Mandatory)][string]$InstanceRoot,[Parameter(Mandatory)][string]$PlanPath)
    $prefix = [IO.Path]::GetFullPath($InstanceRoot).TrimEnd('\','/') + [IO.Path]::DirectorySeparatorChar
    $path = [IO.Path]::GetFullPath($PlanPath)
    if (-not $path.StartsWith($prefix,[StringComparison]::OrdinalIgnoreCase) -or
        [IO.Path]::GetFileName($path) -ne 'deployment-plan.json' -or
        -not (Test-Path -LiteralPath $path -PathType Leaf)) { return $false }
    $cursor = Split-Path -Parent $path
    while ($cursor.Length -ge $prefix.TrimEnd('\','/').Length) {
        if ((Get-Item -LiteralPath $cursor -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) { return $false }
        $cursor = Split-Path -Parent $cursor
    }
    try {
        $plan = Get-Content -Raw -LiteralPath $path | ConvertFrom-Json -AsHashtable
        foreach($name in @('Provider','Instance')){
            if([string]$plan[$name] -notmatch '^[^\\/:*?"<>|\x00-\x1f]+$' -or [string]$plan[$name] -in @('.','..') -or [string]$plan[$name] -match '[. ]$|^(?i:con|prn|aux|nul|com[1-9]|lpt[1-9])(\.|$)'){return $false}
        }
        $archive = [IO.Path]::GetFullPath([string]$plan.Paths.Archive).TrimEnd('\','/')
        $instance=[IO.Path]::GetFullPath([string]$plan.Paths.InstanceDirectory).TrimEnd('\','/')
        $expected=Join-Path (Join-Path $InstanceRoot $plan.Provider) $plan.Instance
        if(-not $instance.Equals([IO.Path]::GetFullPath($expected),[StringComparison]::OrdinalIgnoreCase) -or
            -not $archive.Equals((Join-Path $instance 'May-VPS-Deploy'),[StringComparison]::OrdinalIgnoreCase) -or
            -not [IO.Path]::GetFullPath([string]$plan.Paths.KeyDirectory).Equals((Join-Path $archive 'ssh'),[StringComparison]::OrdinalIgnoreCase)){return $false}
        return $archive.Equals((Split-Path -Parent $path).TrimEnd('\','/'),[StringComparison]::OrdinalIgnoreCase)
    } catch { return $false }
}
Export-ModuleMember -Function Get-VpsGuiDataPaths, Test-VpsGuiPlanPath
