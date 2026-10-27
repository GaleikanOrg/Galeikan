param(
    [switch]$SkipCargoBuild
)

$ErrorActionPreference = 'Stop'
$projectRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$distDir = Join-Path $projectRoot 'dist'
New-Item -ItemType Directory -Force -Path $distDir | Out-Null

if (-not $SkipCargoBuild) {
    Push-Location $projectRoot
    try {
        cargo build --release
        if ($LASTEXITCODE -ne 0) { throw 'cargo build --release failed' }
    } finally { Pop-Location }
}
$binary = Join-Path $projectRoot 'target\release\galeikan.exe'
if (-not (Test-Path -LiteralPath $binary)) { throw "Missing binary: $binary" }
& (Join-Path $PSScriptRoot 'build-vscode-extension.ps1') | Out-Null

$pathHelper = Join-Path $distDir 'galeikan-path.exe'
$pathHelperSource = Join-Path $projectRoot 'packaging\windows\path_helper.c'
& gcc -O2 -std=c11 -Wall -Wextra -Werror -municode -mwindows -static -o $pathHelper $pathHelperSource -ladvapi32 -luser32 -lshell32
if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $pathHelper)) { throw 'Galeikan PATH helper build failed' }

$script = Join-Path $projectRoot 'packaging\windows\Galeikan.nsi'
$output = Join-Path $distDir 'Galeikan-0.1.0-preview2-windows-x64-setup.exe'
$makensis = Get-Command makensis.exe -ErrorAction SilentlyContinue
Push-Location (Split-Path -Parent $script)
try {
    if ($makensis) {
        & $makensis.Source "-DPROJECT_ROOT=$($projectRoot.Replace('\', '/'))" "-DOUTPUT_EXE=$($output.Replace('\', '/'))" $script
    } else {
        $wsl = Get-Command wsl.exe -ErrorAction SilentlyContinue
        if (-not $wsl) { throw 'NSIS makensis was not found; install NSIS or use WSL with makensis.' }
        function ConvertTo-WslPath([string]$path) {
            if ($path -notmatch '^([A-Za-z]):\\(.*)$') { throw "Unsupported WSL path: $path" }
            return '/mnt/' + $matches[1].ToLowerInvariant() + '/' + $matches[2].Replace('\', '/')
        }
        $rootWsl = ConvertTo-WslPath $projectRoot
        $outputWsl = ConvertTo-WslPath $output
        $scriptWsl = ConvertTo-WslPath $script
        & wsl.exe makensis "-DPROJECT_ROOT=$rootWsl" "-DOUTPUT_EXE=$outputWsl" $scriptWsl
    }
} finally { Pop-Location }
if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $output)) { throw 'NSIS installer build failed' }
Write-Output $output
