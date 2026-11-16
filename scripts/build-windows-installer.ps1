param(
    [switch]$SkipCargoBuild,
    [string]$OutputDirectory
)

$ErrorActionPreference = 'Stop'
$projectRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$distDir = Join-Path $projectRoot 'dist'
New-Item -ItemType Directory -Force -Path $distDir | Out-Null
$installerDir = if ($OutputDirectory) { [System.IO.Path]::GetFullPath($OutputDirectory) } else { $distDir }
New-Item -ItemType Directory -Force -Path $installerDir | Out-Null
$cargoManifest = Get-Content -LiteralPath (Join-Path $projectRoot 'Cargo.toml') -Raw
if ($cargoManifest -notmatch '(?m)^version\s*=\s*"([^"]+)"\s*$') { throw 'Missing Galeikan package version' }
$packageVersion = $Matches[1]
$releaseChannel = (Get-Content -LiteralPath (Join-Path $projectRoot 'packaging\release-channel.txt') -Raw).Trim()
if ($releaseChannel -notmatch '^(stable|preview[1-9][0-9]*)$') { throw 'Invalid Galeikan release channel' }
$suffix = if ($releaseChannel -eq 'stable') { '' } else { "-$releaseChannel" }
$productName = if ($releaseChannel -eq 'stable') {
    "Galeikan $packageVersion"
} else {
    "Galeikan $packageVersion Preview $($releaseChannel.Substring(7))"
}

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
$extensionManifest = Get-Content -LiteralPath (Join-Path $projectRoot 'editors\vscode\galeikan\package.json') -Raw | ConvertFrom-Json
$vsix = Join-Path $distDir ("galeikan-language-{0}.vsix" -f $extensionManifest.version)
if (-not (Test-Path -LiteralPath $vsix)) { throw "Missing VS Code extension: $vsix" }

$pathHelper = Join-Path $distDir 'galeikan-path.exe'
$pathHelperSource = Join-Path $projectRoot 'packaging\windows\path_helper.c'
& gcc -O2 -std=c11 -Wall -Wextra -Werror -municode -mwindows -static -o $pathHelper $pathHelperSource -ladvapi32 -luser32 -lshell32
if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $pathHelper)) { throw 'Galeikan PATH helper build failed' }

$script = Join-Path $projectRoot 'packaging\windows\Galeikan.nsi'
$output = Join-Path $installerDir "Galeikan-$packageVersion$suffix-windows-x64-setup.exe"
$makensis = Get-Command makensis.exe -ErrorAction SilentlyContinue
Push-Location (Split-Path -Parent $script)
try {
    if ($makensis) {
        & $makensis.Source "-DPROJECT_ROOT=$($projectRoot.Replace('\', '/'))" "-DOUTPUT_EXE=$($output.Replace('\', '/'))" "-DVSIX_FILE=$($vsix.Replace('\', '/'))" "-DPRODUCT_NAME=$productName" $script
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
        $vsixWsl = ConvertTo-WslPath $vsix
        & wsl.exe makensis "-DPROJECT_ROOT=$rootWsl" "-DOUTPUT_EXE=$outputWsl" "-DVSIX_FILE=$vsixWsl" "-DPRODUCT_NAME=$productName" $scriptWsl
    }
} finally { Pop-Location }
if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $output)) { throw 'NSIS installer build failed' }
Write-Output $output
