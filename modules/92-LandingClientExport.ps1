@{
    Id        = 'landing-client-export'
    Name      = '生成 Shadowsocks 落地客户端私有片段'
    Order     = 92
    Roles     = @('ShadowsocksLanding')
    Requires  = @('sing-box-shadowsocks')
    IsEnabled = { param($Context) $true }
    Invoke    = {
        param($Context)

        $exportDir = Join-Path $Context.ArchivePath 'client-exports'
        [IO.Directory]::CreateDirectory($exportDir) | Out-Null
        $mixedPort = 17893
        $mihomoPath = Join-Path $exportDir 'mihomo-shadowsocks-test.yaml'
        [IO.File]::WriteAllText($mihomoPath, (New-MxhLandingMihomoProfileText -Context $Context -MixedPort $mixedPort), [Text.UTF8Encoding]::new($false))
        Protect-VpsPrivateFile $mihomoPath

        $credentials = $Context.Secrets.Shadowsocks
        $dualStack = [bool]$Context.Plan.Shadowsocks.SecondaryIpv6Enabled
        $outbounds = [Collections.Generic.List[object]]::new()
        $outbounds.Add([ordered]@{
                type = 'shadowsocks'
                tag = (Get-MxhLandingClientNodeName -Plan $Context.Plan -AddressFamily IPv4)
                server = [string]$Context.Plan.Server.IPv4
                server_port = [int]$Context.Plan.Ports.LandingShadowsocks
                method = [string]$Context.Plan.Shadowsocks.Method
                password = ([string]$credentials.ServerKey) + ':' + ([string]$credentials.PrimaryUserKey)
                detour = [string]$Context.Plan.Shadowsocks.ClientTransitTag
            })
        if ([bool]$Context.Plan.Shadowsocks.SecondaryIpv6Enabled) {
            $outbounds.Add([ordered]@{
                    type = 'shadowsocks'
                    tag = (Get-MxhLandingClientNodeName -Plan $Context.Plan -AddressFamily IPv6)
                    server = [string]$Context.Plan.Server.IPv4
                    server_port = [int]$Context.Plan.Ports.LandingShadowsocks
                    method = [string]$Context.Plan.Shadowsocks.Method
                    password = ([string]$credentials.ServerKey) + ':' + ([string]$credentials.SecondaryUserKey)
                    detour = [string]$Context.Plan.Shadowsocks.ClientTransitTag
                })
        }
        $singBoxPath = Join-Path $exportDir 'sing-box-shadowsocks-outbounds.private.json'
        Save-VpsJson -Value ([ordered]@{ outbounds = $outbounds }) -Path $singBoxPath -Private
        $singBoxTestPath = Join-Path $exportDir 'sing-box-shadowsocks-syntax-test.private.json'
        $singTestOutbound = Copy-MxhHashtable -Value $outbounds[0]
        $singTestOutbound.tag = 'proxy'
        $singTestOutbound.detour = [string]$Context.Plan.Shadowsocks.ClientTransitTag
        $singTestConfig = New-MxhSingBoxTestConfig -Outbound $singTestOutbound -MixedPort $mixedPort
        $singTestConfig.outbounds += [ordered]@{ type = 'direct'; tag = [string]$Context.Plan.Shadowsocks.ClientTransitTag }
        Save-VpsJson -Value $singTestConfig -Path $singBoxTestPath -Private

        $notePath = Join-Path $exportDir 'README-shadowsocks-private.txt'
        $note = @"
这些文件包含有效 SS2022 组合密码，只能留在本地私有归档。

Mihomo 文件中的 dialer-proxy 已指向：$($Context.Plan.Shadowsocks.ClientTransitTag)
sing-box 片段中的 detour 已指向同名 tag。合并时必须确认主配置中存在该入口组/tag。

不要把纯落地节点作为受限网络直连入口；服务端防火墙仅允许可信入口 VPS 地址。
"@
        [IO.File]::WriteAllText($notePath, $note, [Text.UTF8Encoding]::new($false))
        Protect-VpsPrivateFile $notePath

        $coreStates = [ordered]@{}
        foreach ($coreName in @('mihomo', 'sing-box')) {
            $coreState = Resolve-VpsClientValidationCore -Context $Context -Core $coreName
            $coreStates[$coreName] = $coreState
            if ($coreState.Status -eq 'SkippedByUser') { continue }
            if ($coreName -eq 'mihomo') {
                $testData = Join-Path $exportDir 'landing-syntax-test-data'
                [IO.Directory]::CreateDirectory($testData) | Out-Null
                $test = Invoke-VpsProcess -FilePath $coreState.Path -ArgumentList @('-t', '-d', $testData, '-f', $mihomoPath) -TimeoutSeconds 120
            }
            else { $test = Invoke-VpsProcess -FilePath $coreState.Path -ArgumentList @('check', '-c', $singBoxTestPath) -TimeoutSeconds 120 }
            if ($test.ExitCode -ne 0) { throw "$coreName Shadowsocks 语法测试失败。" }
        }
        $Context.State.LandingClientExports = [ordered]@{
            MihomoProfile = $mihomoPath
            SingBoxOutbounds = $singBoxPath
            SingBoxSyntaxProfile = $singBoxTestPath
            CoreValidation = $coreStates
        }
        Save-VpsContext -Context $Context
    }
}
