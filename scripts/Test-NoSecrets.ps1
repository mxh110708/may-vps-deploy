[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string]$ProjectRoot
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$excludedDirectories = @('.git', '.test-output', '.tmp', 'TestResults', '.cache', '__pycache__', 'private', 'data', 'state', 'logs', 'exports', 'runtime')
$textExtensions = @('.ps1', '.psm1', '.psd1', '.sh', '.md', '.json', '.yml', '.yaml', '.txt', '.cmd', '.py', '.toml', '.ini', '.cs', '.xaml', '.iss', '.isl', '.manifest')
$privatePaths = '(?i)(^|/)(private|data|state|logs|exports|\.cache|\.tmp|\.test-output|TestResults)/|\.private\.(json|txt)$|(^|/)(root\.txt|params\.json|id_ed25519|id_rsa)$|\.(key|pem)$|^config/(client-layout|app-defaults)\.local\.json$'
$patterns = [ordered]@{
    'Private key block' = '-----BEGIN (?:OPENSSH |RSA |EC )?PRIVATE KEY-----'
    'ECH server key block' = '-----BEGIN ECH KEYS-----\s*[A-Za-z0-9+/=\r\n]{80,}\s*-----END ECH KEYS-----'
    'GitHub token' = '\b(?:ghp|github_pat)_[A-Za-z0-9_]{20,}\b'
    'Cloudflare tunnel token' = '\beyJ[a-zA-Z0-9_-]{40,}\.[a-zA-Z0-9_-]{20,}\.[a-zA-Z0-9_-]{20,}\b'
    'Concrete UUID' = '(?i)\b[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\b'
    'Accidental root credential file' = '(?i)(^|[\\/])root\.txt$'
    'Accidental params file' = '(?i)(^|[\\/])params\.json$'
    'Accidental Cloudflare credential file' = '(?i)(^|[\\/])cloudflare-(?:certbot|dns|api)[^\\/]*\.(?:txt|ini)$'
}

$findings = [Collections.Generic.List[object]]::new()
$ProjectRoot=[IO.Path]::GetFullPath($ProjectRoot)
$git=Get-Command git -ErrorAction SilentlyContinue
$gitRoot=if($git){& $git.Source -c "safe.directory=$ProjectRoot" -C $ProjectRoot rev-parse --show-toplevel 2>$null}else{''}
$useGit=$git -and $LASTEXITCODE -eq 0 -and $gitRoot -and [IO.Path]::GetFullPath([string]$gitRoot) -eq $ProjectRoot
if($useGit){
    # Honor .gitignore for local runtime files, but never hide a private file in the index.
    $paths=@(& $git.Source -c "safe.directory=$ProjectRoot" -c core.quotepath=false -c core.excludesFile= -C $ProjectRoot ls-files --cached --others --exclude-standard 2>$null|Sort-Object -Unique)
    if($LASTEXITCODE -ne 0){throw '无法读取 Git 文件清单，保密检查未通过。'}
    $files=@(foreach($relative in $paths){
        if($relative -match $privatePaths){$findings.Add([pscustomobject]@{Rule='Private/runtime file in public tree'; File=$relative})}
        $path=[IO.Path]::GetFullPath((Join-Path $ProjectRoot $relative))
        if(-not $path.StartsWith($ProjectRoot+[IO.Path]::DirectorySeparatorChar,[StringComparison]::OrdinalIgnoreCase)){throw 'Git 文件路径越界。'}
        if(Test-Path -LiteralPath $path -PathType Leaf){$file=Get-Item -LiteralPath $path;if($file.Extension -in $textExtensions){$file}}
    })
}else{
    # Source ZIPs have no index; apply the documented runtime boundary, not a guessed parent repository.
    $files=@(Get-ChildItem -LiteralPath $ProjectRoot -Recurse -File | Where-Object {
        $relative=[IO.Path]::GetRelativePath($ProjectRoot,$_.FullName).Replace('\','/')
        $runtime=$relative.Split('/') | Where-Object { $_ -in $excludedDirectories }
        $localOnly=$relative -match '(?i)\.private\.(json|txt)$|^config/(client-layout|app-defaults)\.local\.json$'
        if(-not $runtime -and -not $localOnly -and $relative -match $privatePaths){$findings.Add([pscustomobject]@{Rule='Credential file outside runtime boundary';File=$relative})}
        $_.Extension -in $textExtensions -and -not $runtime -and -not $localOnly
    })
}
foreach ($file in $files) {
    $relative = [IO.Path]::GetRelativePath($ProjectRoot, $file.FullName)
    $content = Get-Content -Raw -LiteralPath $file.FullName
    foreach ($entry in $patterns.GetEnumerator()) {
        $target = if ($entry.Key -like 'Accidental*') { $relative } else { $content }
        # Public Windows 10/11 supportedOS compatibility identifier, not a node UUID.
        # Limit the exception to this exact XML element; other UUIDs still fail.
        if($entry.Key -eq 'Concrete UUID' -and $file.Extension -eq '.manifest'){
            $publicWindowsCompatibility='8e0f7a12-'+'bfb3-'+'4fe8-'+'b9a5-'+'48fd50a15a9a'
            $target=$target -replace ('<supportedOS\s+Id="\{'+[regex]::Escape($publicWindowsCompatibility)+'\}"\s*/>'), '<supportedOS />'
        }
        # Published Windows Shell COM identifiers in their exact declarations.
        # Do not exempt other UUIDs or copies in configuration/public documents.
        if($entry.Key -eq 'Concrete UUID' -and $relative.Replace('\','/') -eq 'desktop/May.VpsDeploy.Windows/WindowsSavePathPicker.cs'){
            $saveDialog='C0B4E2F3-'+'BA21-'+'4773-'+'8DBA-'+'335EC946EB8B'
            $fileDialog='42F85136-'+'DB7E-'+'439C-'+'85F1-'+'E4075D135FC8'
            $shellItem='43826D1E-'+'E718-'+'42EE-'+'BC55-'+'A1E261C37BFE'
            $target=$target.Replace(('Type.GetTypeFromCLSID(new("'+$saveDialog+'"), true)'), 'Type.GetTypeFromCLSID(publicWindowsSaveDialog, true)')
            foreach($identifier in @($fileDialog,$shellItem)){$target=$target.Replace(('[ComImport, Guid("'+$identifier+'")'), '[ComImport, publicWindowsShellInterface')}
        }
        if ($target -match $entry.Value) {
            $findings.Add([pscustomobject]@{ Rule = $entry.Key; File = $relative })
        }
    }
}

if ($findings.Count -gt 0) {
    $findings | Sort-Object Rule, File | Format-Table -AutoSize
    throw '检测到可能的实例秘密或私有归档文件。'
}
Write-Host "Secret scan passed: $($files.Count) text files" -ForegroundColor Green
