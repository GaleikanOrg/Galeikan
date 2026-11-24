$ErrorActionPreference = 'Stop'
$projectRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$extensionRoot = Join-Path $projectRoot 'editors\vscode\galeikan'
$manifest = Get-Content -LiteralPath (Join-Path $extensionRoot 'package.json') -Raw | ConvertFrom-Json
$output = Join-Path $projectRoot ("dist\galeikan-language-{0}.vsix" -f $manifest.version)
$themeRoot = Join-Path $projectRoot 'editors\vscode\galeikan-eclipse'
$themeManifest = Get-Content -LiteralPath (Join-Path $themeRoot 'package.json') -Raw | ConvertFrom-Json
$themeOutput = Join-Path $projectRoot ("dist\galeikan-eclipse-{0}.vsix" -f $themeManifest.version)
$npx = Get-Command npx.cmd -ErrorAction Stop
New-Item -ItemType Directory -Force -Path (Split-Path -Parent $output) | Out-Null
Push-Location $extensionRoot
try {
    & $npx.Source --yes @vscode/vsce package --no-dependencies --allow-missing-repository --out $output
    if ($LASTEXITCODE -ne 0) { throw 'VS Code extension packaging failed' }
} finally { Pop-Location }
if (-not (Test-Path -LiteralPath $output)) { throw "Missing VSIX: $output" }
Push-Location $themeRoot
try {
    & $npx.Source --yes @vscode/vsce package --no-dependencies --allow-missing-repository --out $themeOutput
    if ($LASTEXITCODE -ne 0) { throw 'VS Code theme packaging failed' }
} finally { Pop-Location }
if (-not (Test-Path -LiteralPath $themeOutput)) { throw "Missing VSIX: $themeOutput" }
Write-Output $output
Write-Output $themeOutput
