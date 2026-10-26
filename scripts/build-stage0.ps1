$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path -Parent $PSScriptRoot
$buildDir = Join-Path $projectRoot 'build'
New-Item -ItemType Directory -Path $buildDir -Force | Out-Null
& gcc -Wall -Wextra -o (Join-Path $buildDir 'galeikan-script.exe') (Join-Path $projectRoot 'stage0\main.S')
if ($LASTEXITCODE -ne 0) { throw 'Stage 0 build failed.' }
Write-Host "Built: $(Join-Path $buildDir 'galeikan-script.exe')"
