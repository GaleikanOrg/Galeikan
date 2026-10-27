$ErrorActionPreference = 'Stop'
$projectRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$extensionRoot = Join-Path $projectRoot 'editors\vscode\galeikan'
$manifest = Get-Content -LiteralPath (Join-Path $extensionRoot 'package.json') -Raw | ConvertFrom-Json
$output = Join-Path $projectRoot ("dist\galeikan-language-{0}.vsix" -f $manifest.version)
$npx = Get-Command npx.cmd -ErrorAction Stop
New-Item -ItemType Directory -Force -Path (Split-Path -Parent $output) | Out-Null
Push-Location $extensionRoot
try {
    & $npx.Source --yes @vscode/vsce package --no-dependencies --allow-missing-repository --out $output
    if ($LASTEXITCODE -ne 0) { throw 'VS Code extension packaging failed' }
} finally { Pop-Location }
if (-not (Test-Path -LiteralPath $output)) { throw "Missing VSIX: $output" }
Write-Output $output
