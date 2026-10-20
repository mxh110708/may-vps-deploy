[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$SessionManifest,
    [Parameter(Mandatory)][string]$Command,
    [hashtable]$Arguments = @{},
    [int]$TimeoutSeconds = 20
)
$ErrorActionPreference = 'Stop'
$session = Get-Content -Raw -LiteralPath $SessionManifest | ConvertFrom-Json
if ($session.SchemaVersion -ne 1 -or $session.PipeName -notmatch '^may-test-[a-f0-9]{32}$') { throw 'Invalid test manifest.' }
$pipe = [IO.Pipes.NamedPipeClientStream]::new('.', $session.PipeName, [IO.Pipes.PipeDirection]::InOut, [IO.Pipes.PipeOptions]::Asynchronous -bor [IO.Pipes.PipeOptions]::CurrentUserOnly)
$timeout = [Threading.CancellationTokenSource]::new([TimeSpan]::FromSeconds($TimeoutSeconds))
try {
    $null = $pipe.ConnectAsync(5000, $timeout.Token).GetAwaiter().GetResult()
    $id = [guid]::NewGuid().ToString('N')
    $request = @{version=1;id=$id;token=$session.Token;command=$Command;arguments=$Arguments} | ConvertTo-Json -Depth 20 -Compress
    $bytes = [Text.Encoding]::UTF8.GetBytes($request + "`n")
    if ($bytes.Length -gt 1MB) { throw 'Test request too large.' }
    $null = $pipe.WriteAsync($bytes,0,$bytes.Length,$timeout.Token).GetAwaiter().GetResult()
    $null = $pipe.FlushAsync($timeout.Token).GetAwaiter().GetResult()
    $reader = [IO.StreamReader]::new($pipe,[Text.Encoding]::UTF8,$false,4096,$true)
    try { $line = $reader.ReadLineAsync($timeout.Token).GetAwaiter().GetResult() } finally { $reader.Dispose() }
    if (-not $line -or $line.Length -gt 1MB) { throw 'Test response missing or too large.' }
    $response = $line | ConvertFrom-Json -Depth 30
    if ($response.id -ne $id -or $response.version -ne 1) { throw 'Test response mismatch.' }
    if (-not $response.ok) { throw ($response.error_code + ': ' + $response.message) }
    $response.result
} finally { $timeout.Dispose(); $pipe.Dispose(); $session.Token = $null }
