[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string]$ProjectRoot,
    [Parameter(Mandatory)] [string]$SingBoxPath,
    [string]$FixtureOutputDirectory
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

Import-Module (Join-Path $ProjectRoot 'src\VpsDeploy.Core.psm1') -Force
$work = if($FixtureOutputDirectory){[IO.Path]::GetFullPath($FixtureOutputDirectory)}else{Join-Path ([IO.Path]::GetTempPath()) ('mxh-sing-box-check-' + [guid]::NewGuid().ToString('N'))}
if(Test-Path -LiteralPath $work){throw '隔离夹具输出目录必须尚不存在。'}
[IO.Directory]::CreateDirectory($work) | Out-Null
try {
    $serverKey = [Convert]::ToBase64String([byte[]](1..16))
    $primaryUserKey = [Convert]::ToBase64String([byte[]](17..32))
    $secondaryUserKey = [Convert]::ToBase64String([byte[]](33..48))
    $context = [pscustomobject]@{
        Plan = [ordered]@{
            NodeName = 'Example-US.Landing'
            Server = [ordered]@{ IPv4 = '192.0.2.20'; IPv6 = '2001:db8::20' }
            Ports = [ordered]@{ LandingShadowsocks = 33456 }
            Shadowsocks = [ordered]@{
                Method = '2022-blake3-aes-128-gcm'
                SecondaryIpv6Enabled = $true
                SecondaryIpv6Address = '2001:db8::20'
                SecondaryBindInterface = 'eth0'
                ClientTransitTag = 'US-West-LA Entry'
            }
        }
        Secrets = [ordered]@{
            Shadowsocks = [ordered]@{
                ServerKey = $serverKey
                PrimaryUserKey = $primaryUserKey
                SecondaryUserKey = $secondaryUserKey
            }
        }
    }
    $serverPath = Join-Path $work 'server.json'
    $serverConfig = New-MxhShadowsocksServerConfig -Context $context
    if ($serverConfig.route.Contains('auto_detect_interface')) {
        throw 'Shadowsocks server must not require interface auto-detection under the default capability-free service account.'
    }
    [IO.File]::WriteAllText($serverPath, ($serverConfig | ConvertTo-Json -Depth 30), [Text.UTF8Encoding]::new($false))

    $clientPath = Join-Path $work 'client.json'
    $clientConfig = [ordered]@{
        log = [ordered]@{ level = 'warn' }
        inbounds = @([ordered]@{
                type = 'direct'
                tag = 'udp-test-in'
                listen = '127.0.0.1'
                listen_port = 35353
                network = 'udp'
                override_address = '1.1.1.1'
                override_port = 53
            })
        outbounds = @(
            [ordered]@{ type = 'direct'; tag = 'US-West-LA Entry' },
            [ordered]@{
                type = 'shadowsocks'
                tag = 'landing'
                server = '192.0.2.20'
                server_port = 33456
                method = '2022-blake3-aes-128-gcm'
                password = $serverKey + ':' + $primaryUserKey
                detour = 'US-West-LA Entry'
            }
        )
        route = [ordered]@{ final = 'landing' }
    }
    [IO.File]::WriteAllText($clientPath, ($clientConfig | ConvertTo-Json -Depth 30), [Text.UTF8Encoding]::new($false))

    foreach ($config in @($serverPath, $clientPath)) {
        & $SingBoxPath check -c $config
        if ($LASTEXITCODE -ne 0) { throw "sing-box config check failed: $config" }
    }

    $genericTemplate=Join-Path $ProjectRoot 'templates\client\sing-box-general.template.json'
    $genericCheck = Invoke-MxhSingBoxCandidateCheck -ProjectRoot $ProjectRoot -CorePath $SingBoxPath -ConfigPath $genericTemplate
    if($genericCheck.ExitCode-ne 0){throw "generic sing-box authority template check failed: $($genericCheck.StdErr)"}
    $genericConfig = Get-Content -Raw -LiteralPath $genericTemplate | ConvertFrom-Json -AsHashtable
    $genericMixed = @($genericConfig.inbounds | Where-Object { [string]$_.type -eq 'mixed' })
    $genericTun = @($genericConfig.inbounds | Where-Object { [string]$_.type -eq 'tun' })
    if ($genericMixed.Count -ne 1 -or $genericTun.Count -ne 1) {
        throw 'generic sing-box authority template must support both system-proxy and TUN capture modes'
    }
    if ([string]$genericTun[0].dns_mode -ne 'hijack' -or -not [bool]$genericTun[0].auto_route -or -not [bool]$genericTun[0].strict_route) {
        throw 'generic sing-box authority template must keep the 1.14 TUN DNS and routing contract'
    }
    $genericDnsHijack = @($genericConfig.route.rules | Where-Object {
            $_.Contains('protocol') -and [string]$_['protocol'] -eq 'dns' -and
            $_.Contains('action') -and [string]$_['action'] -eq 'hijack-dns'
        })
    if ($genericDnsHijack.Count -ne 1) {
        throw 'generic sing-box authority template must contain exactly one DNS hijack rule'
    }

    $echOutput = (& $SingBoxPath generate ech-keypair 'www.example.invalid' 2>&1) -join "`n"
    if ($LASTEXITCODE -ne 0) { throw 'sing-box ECH keypair generation failed' }
    $ech = ConvertFrom-MxhEchKeyPairText -Text $echOutput
    $echKeyPath = Join-Path $work 'ech-key.pem'
    $echConfigPath = Join-Path $work 'ech-config.pem'
    [IO.File]::WriteAllText($echKeyPath, $ech.ServerKeyPem, [Text.UTF8Encoding]::new($false))
    [IO.File]::WriteAllText($echConfigPath, $ech.ClientConfigPem, [Text.UTF8Encoding]::new($false))

    $rsa = [Security.Cryptography.RSA]::Create(2048)
    try {
        $request = [Security.Cryptography.X509Certificates.CertificateRequest]::new(
            'CN=edge.example.invalid', $rsa, [Security.Cryptography.HashAlgorithmName]::SHA256,
            [Security.Cryptography.RSASignaturePadding]::Pkcs1)
        $san = [Security.Cryptography.X509Certificates.SubjectAlternativeNameBuilder]::new()
        $san.AddDnsName('edge.example.invalid')
        $san.AddDnsName('www.example.invalid')
        $request.CertificateExtensions.Add($san.Build())
        $cert = $request.CreateSelfSigned((Get-Date).AddMinutes(-5), (Get-Date).AddDays(3))
        try {
            $certPath = Join-Path $work 'anytls-cert.pem'
            $keyPath = Join-Path $work 'anytls-key.pem'
            [IO.File]::WriteAllText($certPath, $cert.ExportCertificatePem(), [Text.UTF8Encoding]::new($false))
            [IO.File]::WriteAllText($keyPath, $rsa.ExportPkcs8PrivateKeyPem(), [Text.UTF8Encoding]::new($false))
        }
        finally { $cert.Dispose() }
    }
    finally { $rsa.Dispose() }

    $anyTlsContext = [pscustomobject]@{
        Plan = [ordered]@{
            NodeName = 'Example-US.AnyTLS'
            Server = [ordered]@{ IPv4 = '192.0.2.40'; IPv6 = '2001:db8::40' }
            Ports = [ordered]@{ AnyTlsPrimary = 443 }
            AnyTls = [ordered]@{
                ServerName = 'edge.example.invalid'
                EchPublicName = 'www.example.invalid'
                ForceIpv4Egress = $true
                PaddingSchemeMode = 'PerInstanceConservativeV1'
                PaddingScheme = @(
                    'stop=8', '0=28-64', '1=120-360',
                    '2=420-540,c,520-900,c,540-920,c,560-940,c,580-960',
                    '3=12-20,520-920', '4=500-880', '5=540-940', '6=560-980', '7=600-1000'
                )
            }
        }
        Secrets = [ordered]@{
            AnyTls = [ordered]@{
                Password = [Convert]::ToBase64String([byte[]](49..80))
                EchServerKeyPem = $ech.ServerKeyPem
                EchClientConfigPem = $ech.ClientConfigPem
                EchClientConfigBase64 = $ech.ClientConfigBase64
            }
        }
    }
    $anyTlsServer = New-MxhAnyTlsServerConfig -Context $anyTlsContext
    if ($anyTlsServer.route.Contains('auto_detect_interface')) {
        throw 'AnyTLS server must not require interface auto-detection under the low-privilege service account.'
    }
    if (@($anyTlsServer.inbounds[0].padding_scheme).Count -ne 9) {
        throw 'AnyTLS server padding scheme was not generated.'
    }
    $anyTlsServer.inbounds[0].tls.certificate_path = $certPath
    $anyTlsServer.inbounds[0].tls.key_path = $keyPath
    $anyTlsServer.inbounds[0].tls.ech.key_path = $echKeyPath
    $anyTlsServerPath = Join-Path $work 'anytls-server.json'
    [IO.File]::WriteAllText($anyTlsServerPath, ($anyTlsServer | ConvertTo-Json -Depth 30), [Text.UTF8Encoding]::new($false))

    $anyTlsClientPath = Join-Path $work 'anytls-client.json'
    $anyTlsClient = [ordered]@{
        log = [ordered]@{ level = 'warn' }
        outbounds = @((New-MxhAnyTlsClientOutbound -Context $anyTlsContext -Server '192.0.2.40' -Tag 'anytls-out'))
        route = [ordered]@{ final = 'anytls-out' }
    }
    [IO.File]::WriteAllText($anyTlsClientPath, ($anyTlsClient | ConvertTo-Json -Depth 30), [Text.UTF8Encoding]::new($false))
    foreach ($config in @($anyTlsServerPath, $anyTlsClientPath)) {
        & $SingBoxPath check -c $config
        if ($LASTEXITCODE -ne 0) { throw "sing-box AnyTLS/ECH config check failed: $config" }
    }
    Write-Host 'Exact sing-box core checks passed.' -ForegroundColor Green
}
finally {
    if (-not $FixtureOutputDirectory -and (Test-Path -LiteralPath $work)) { [IO.Directory]::Delete($work, $true) }
}
