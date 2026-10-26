$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path -Parent $PSScriptRoot
& (Join-Path $PSScriptRoot 'build-stage0.ps1')

$exe = Join-Path $projectRoot 'build\galeikan-script.exe'
$testDir = Join-Path $projectRoot 'build\stage0-tests'
New-Item -ItemType Directory -Path $testDir -Force | Out-Null
$utf8 = New-Object System.Text.UTF8Encoding($false)

function Assert-Program {
    param([string]$Name, [string]$Source, [int]$ExpectedExit, [string]$ExpectedOutput, [string[]]$Arguments = @())
    $file = Join-Path $testDir "$Name.gak"
    [System.IO.File]::WriteAllText($file, $Source, $utf8)
    $lines = & $exe @Arguments $file
    $actualExit = $LASTEXITCODE
    $actualOutput = ($lines -join "`n").TrimEnd("`r", "`n")
    if ($actualExit -ne $ExpectedExit -or $actualOutput -ne $ExpectedOutput) {
        throw "$Name failed: exit=$actualExit, output='$actualOutput'"
    }
    Write-Host "OK: $Name"
}

Assert-Program 'text-and-number' "# Comment`nprint `"Hello`"`nprint -42`n" 0 "Hello`n-42"
Assert-Program 'trailing-comment' "print 7 # Comment`n" 0 '7'
Assert-Program 'missing-number' "print `n" 2 'Syntax error on line 1.'
Assert-Program 'unknown-statement' "let x = 1`n" 2 'Syntax error on line 1.'
Assert-Program 'overflow' "print 9223372036854775808`n" 2 'Syntax error on line 1.'
Assert-Program 'minimum-integer' "print -9223372036854775808`n" 0 '-9223372036854775808'
Assert-Program 'line-too-long' ("print `"" + ('x' * 4090) + "`"`n") 2 'Syntax error on line 1.'

$fixture = Join-Path $testDir 'header.bin'
[System.IO.File]::WriteAllBytes($fixture, [byte[]](0x47, 0x41, 0x4b, 0x00))
$fixturePath = $fixture.Replace('\', '/')
$declaration = "requires { file.read }`n"
$observation = "${declaration}observe `"$fixturePath`" at 0 as u16le`n"
Assert-Program 'observation' $observation 0 "$fixturePath @ 0 u16le = 16711" @('--allow-read')
Assert-Program 'permission-missing' $observation 3 'observe requires --allow-read (line 2).'
Assert-Program 'declaration-missing' "observe `"$fixturePath`" at 0 as u8`n" 3 'observe requires { file.read } (line 1).' @('--allow-read')
Assert-Program 'out-of-bounds' "${declaration}observe `"$fixturePath`" at 3 as u16le`n" 3 "Observation failed: $fixturePath @ 3 (file/range)." @('--allow-read')
Assert-Program 'negative-offset' "${declaration}observe `"$fixturePath`" at -1 as u8`n" 2 'Syntax error on line 2.' @('--allow-read')
Assert-Program 'invalid-type' "${declaration}observe `"$fixturePath`" at 0 as u64le`n" 2 'Syntax error on line 2.' @('--allow-read')
Assert-Program 'late-declaration' "print 1`n$declaration" 2 "1`nSyntax error on line 2."
