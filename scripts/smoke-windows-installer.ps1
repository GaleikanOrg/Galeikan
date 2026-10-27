$ErrorActionPreference = 'Stop'
$utf8NoBom = New-Object System.Text.UTF8Encoding($false)
$projectRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$installer = Join-Path $projectRoot 'dist\Galeikan-0.1.0-preview2-windows-x64-setup.exe'
$smokeRoot = [System.IO.Path]::GetFullPath((Join-Path $projectRoot "dist\install-smoke-$PID"))
$projectPrefix = $projectRoot.TrimEnd('\') + '\'
if (-not $smokeRoot.StartsWith($projectPrefix, [System.StringComparison]::OrdinalIgnoreCase)) {
    throw "Smoke installation must stay inside the project: $smokeRoot"
}
if (-not (Test-Path -LiteralPath $installer)) { throw "Missing installer: $installer" }
if (Test-Path -LiteralPath $smokeRoot) { throw "Smoke target already exists: $smokeRoot" }
if (Test-Path -LiteralPath 'Registry::HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Uninstall\Galeikan') {
    throw 'A Galeikan installation already exists; the isolated smoke test will not overwrite it'
}
$registryEnvironment = [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey('Environment')
$originalUserPath = $registryEnvironment.GetValue('Path', '', [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
$registryEnvironment.Dispose()

function Remove-SmokeFiles([string[]]$Paths) {
    $smokePrefix = $smokeRoot.TrimEnd('\') + '\'
    foreach ($path in $Paths) {
        $absolute = [System.IO.Path]::GetFullPath($path)
        if (-not $absolute.StartsWith($smokePrefix, [System.StringComparison]::OrdinalIgnoreCase)) {
            throw "Smoke cleanup path escaped the installation: $absolute"
        }
        for ($attempt = 0; $attempt -lt 20; $attempt++) {
            try {
                Remove-Item -LiteralPath $absolute -ErrorAction Stop
                break
            } catch {
                if ($attempt -eq 19 -or
                    ($_.Exception -isnot [System.UnauthorizedAccessException] -and
                     $_.Exception -isnot [System.IO.IOException])) {
                    throw
                }
                Start-Sleep -Milliseconds 250
            }
        }
    }
}

function Remove-CaseArtifact([string]$casePath) {
    $archive = "$casePath.blobs"
    if (Test-Path -LiteralPath $archive) {
        Get-ChildItem -LiteralPath $archive -File | ForEach-Object {
            Remove-Item -LiteralPath $_.FullName
        }
        Remove-Item -LiteralPath $archive
    }
    Remove-Item -LiteralPath $casePath
}

$install = Start-Process -FilePath $installer -ArgumentList '/S', "/D=$smokeRoot" -Wait -PassThru -WindowStyle Hidden
if ($install.ExitCode -ne 0) { throw "Silent install failed with exit code $($install.ExitCode)" }
$registryEnvironment = [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey('Environment')
$installedUserPath = $registryEnvironment.GetValue('Path', '', [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
$registryEnvironment.Dispose()
if (-not $installedUserPath.EndsWith(";$smokeRoot") -and $installedUserPath -ne $smokeRoot) {
    throw 'Installer did not add Galeikan to the user PATH'
}
$appPath = (Get-Item -LiteralPath 'Registry::HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\App Paths\galeikan.exe').GetValue('')
if ($appPath -ne (Join-Path $smokeRoot 'galeikan.exe')) { throw 'Installer did not register the CLI App Path' }
$binary = Join-Path $smokeRoot 'galeikan.exe'
$example = Join-Path $smokeRoot 'examples\hello.gak'
if (-not (Test-Path -LiteralPath $binary) -or -not (Test-Path -LiteralPath $example)) {
    throw 'Installer did not produce the expected binary and example.'
}
if (-not (Test-Path -LiteralPath (Join-Path $smokeRoot 'icons\galeikan.ico')) -or
    -not (Test-Path -LiteralPath (Join-Path $smokeRoot 'editor\galeikan-language-0.1.1.vsix')) -or
    -not (Test-Path -LiteralPath (Join-Path $smokeRoot 'editor\vscode\package.json'))) {
    throw 'Installed file icons or editor assets are missing'
}
$installedVsix = Join-Path $smokeRoot 'editor\galeikan-language-0.1.1.vsix'
$builtVsix = Join-Path $projectRoot 'dist\galeikan-language-0.1.1.vsix'
if ((Get-FileHash -LiteralPath $installedVsix -Algorithm SHA256).Hash -ne
    (Get-FileHash -LiteralPath $builtVsix -Algorithm SHA256).Hash) {
    throw 'Installed VS Code extension does not match the current build'
}
foreach ($asset in @('package.json', 'language-configuration.json', 'syntaxes\galeikan.tmLanguage.json', 'themes\galeikan-noir-color-theme.json')) {
    $installedAsset = Join-Path (Join-Path $smokeRoot 'editor\vscode') $asset
    $sourceAsset = Join-Path (Join-Path $projectRoot 'editors\vscode\galeikan') $asset
    if (-not (Test-Path -LiteralPath $installedAsset) -or
        (Get-FileHash -LiteralPath $installedAsset -Algorithm SHA256).Hash -ne
        (Get-FileHash -LiteralPath $sourceAsset -Algorithm SHA256).Hash) {
        throw "Installed editor asset is missing or outdated: $asset"
    }
}
foreach ($asset in @('pyproject.toml', 'galeikan_bridge\__init__.py', 'galeikan_bridge\_runner.py')) {
    $installedAsset = Join-Path (Join-Path $smokeRoot 'python') $asset
    $sourceAsset = Join-Path (Join-Path $projectRoot 'python') $asset
    if (-not (Test-Path -LiteralPath $installedAsset) -or
        (Get-FileHash -LiteralPath $installedAsset -Algorithm SHA256).Hash -ne
        (Get-FileHash -LiteralPath $sourceAsset -Algorithm SHA256).Hash) {
        throw "Installed Python bridge is missing or outdated: $asset"
    }
}
$installedLogo = Join-Path $smokeRoot 'brand\logo_GaleikanEcosystem.jpg'
$sourceLogo = Join-Path $projectRoot 'logo_GaleikanEcosystem.jpg'
if (-not (Test-Path -LiteralPath $installedLogo) -or
    (Get-FileHash -LiteralPath $installedLogo -Algorithm SHA256).Hash -ne
    (Get-FileHash -LiteralPath $sourceLogo -Algorithm SHA256).Hash) {
    throw 'Installed Ecosystem artwork does not match the supplied image'
}
$langIcon = (Get-Item -LiteralPath 'Registry::HKEY_CURRENT_USER\Software\Classes\Galeikan.Lang\DefaultIcon').GetValue('')
$scriptIcon = (Get-Item -LiteralPath 'Registry::HKEY_CURRENT_USER\Software\Classes\Galeikan.Script\DefaultIcon').GetValue('')
if ($langIcon -ne (Join-Path $smokeRoot 'icons\galeikan.ico') -or $scriptIcon -ne $langIcon) {
    throw 'Installed Galeikan file type icon registration is invalid'
}
$productName = (Get-Item -LiteralPath 'Registry::HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Uninstall\Galeikan').GetValue('DisplayName')
if ($productName -ne 'Galeikan 0.1.0 Preview 2') { throw 'Installed product name is not Galeikan' }
$installedGuide = Join-Path $smokeRoot 'docs\quickstart.md'
$sourceGuide = Join-Path $projectRoot 'packaging\docs\quickstart.md'
if (-not (Test-Path -LiteralPath $installedGuide) -or
    (Get-FileHash -LiteralPath $installedGuide -Algorithm SHA256).Hash -ne
    (Get-FileHash -LiteralPath $sourceGuide -Algorithm SHA256).Hash) {
    throw 'Installed English guide does not match the current source.'
}
$installedReadme = Join-Path $smokeRoot 'README.md'
$sourceReadme = Join-Path $projectRoot 'packaging\README.md'
if (-not (Test-Path -LiteralPath $installedReadme) -or
    (Get-FileHash -LiteralPath $installedReadme -Algorithm SHA256).Hash -ne
    (Get-FileHash -LiteralPath $sourceReadme -Algorithm SHA256).Hash -or
    (Get-ChildItem -LiteralPath (Join-Path $smokeRoot 'docs') -File).Count -ne 1) {
    throw 'Installer contains unexpected or outdated documentation.'
}
& $binary check $example
if ($LASTEXITCODE -ne 0) { throw 'Installed CLI check failed' }
$gaks = Join-Path $smokeRoot 'syntax-smoke.gaks'
[System.IO.File]::WriteAllText($gaks, "print 42`n")
& $binary check $gaks
if ($LASTEXITCODE -ne 0) { throw 'Installed .gaks check failed' }
$gaksOutput = & $binary run $gaks --engine vm
if ($LASTEXITCODE -ne 0 -or ($gaksOutput -join "`n") -ne '42') { throw 'Installed .gaks VM failed' }
& $binary build $gaks
if ($LASTEXITCODE -ne 0) { throw 'Installed .gaks bundle build failed' }
$gaksBundle = [System.IO.Path]::ChangeExtension($gaks, '.gakb')
$gaksOutput = & $binary exec $gaksBundle
if ($LASTEXITCODE -ne 0 -or ($gaksOutput -join "`n") -ne '42') { throw 'Installed .gaks bundle failed' }
& $binary compile $gaks
if ($LASTEXITCODE -ne 0) { throw 'Installed .gaks native compile failed' }
$gaksOutput = & "$gaks.exe"
if ($LASTEXITCODE -ne 0 -or ($gaksOutput -join "`n") -ne '42') { throw 'Installed .gaks native execution failed' }
Remove-Item -LiteralPath $gaks, $gaksBundle, "$gaks.exe", "$gaks.win64.S"
$nativeReadSource = Join-Path $smokeRoot 'native-read-smoke.gak'
$nativeReadSample = Join-Path $smokeRoot 'native-read.bin'
[System.IO.File]::WriteAllBytes($nativeReadSample, [byte[]](0x47, 0x41, 0x4b))
[System.IO.File]::WriteAllText($nativeReadSource, "requires { file.read }`nfrom std.binary import analyze, size`nprint size(analyze(`"native-read.bin`", 16))`n")
& $binary compile $nativeReadSource
if ($LASTEXITCODE -ne 0) { throw 'Installed native file-read compile failed' }
$nativeReadExecutable = "$nativeReadSource.exe"
$nativeReadOutput = & $nativeReadExecutable --allow-read $smokeRoot
if ($LASTEXITCODE -ne 0 -or ($nativeReadOutput -join "`n") -ne '3') {
    throw 'Installed native file-read execution failed'
}
$nativeReadError = Join-Path $smokeRoot 'native-read-denied.err'
$nativeReadDenied = Start-Process -FilePath $nativeReadExecutable -Wait -PassThru -WindowStyle Hidden -RedirectStandardError $nativeReadError
if ($nativeReadDenied.ExitCode -eq 0 -or
    -not (Get-Content -LiteralPath $nativeReadError -Raw).Contains('file access not allowed')) {
    throw 'Installed native file-read permission check failed'
}
Remove-Item -LiteralPath $nativeReadSource, $nativeReadSample, $nativeReadExecutable, $nativeReadError, "$nativeReadSource.win64.S", "$nativeReadSource.native_file.c"
$recordSource = Join-Path $smokeRoot 'struct-smoke.gak'
[System.IO.File]::WriteAllText($recordSource, "struct Header { marker: str, offset: i64 }`nlet header = Header(`"MZ`", 4)`nprint header.marker`nprint header.offset`n")
$recordVm = & $binary run $recordSource --engine vm
if ($LASTEXITCODE -ne 0 -or ($recordVm -join "`n") -ne "MZ`n4") { throw 'Installed struct VM failed' }
& $binary compile $recordSource
if ($LASTEXITCODE -ne 0) { throw 'Installed struct native compile failed' }
$recordNative = & "$recordSource.exe"
if ($LASTEXITCODE -ne 0 -or ($recordNative -join "`n") -ne "MZ`n4") { throw 'Installed struct native execution failed' }
Remove-Item -LiteralPath $recordSource, "$recordSource.exe", "$recordSource.win64.S"
$loopSource = Join-Path $smokeRoot 'loop-smoke.gaks'
[System.IO.File]::WriteAllText($loopSource, @'
var count = 0
while count < 5 {
    count = count + 1
    if count == 2 {
        continue
    }
    if count == 4 {
        break
    }
    print count
}
'@)
$loopVm = & $binary run $loopSource --engine vm
if ($LASTEXITCODE -ne 0 -or ($loopVm -join "`n") -ne "1`n3") { throw 'Installed loop control VM failed' }
& $binary compile $loopSource
if ($LASTEXITCODE -ne 0) { throw 'Installed loop control native compile failed' }
$loopNative = & "$loopSource.exe"
if ($LASTEXITCODE -ne 0 -or ($loopNative -join "`n") -ne "1`n3") { throw 'Installed loop control native execution failed' }
Remove-Item -LiteralPath $loopSource, "$loopSource.exe", "$loopSource.win64.S"
$classSource = Join-Path $smokeRoot 'class-smoke.gak'
[System.IO.File]::WriteAllText($classSource, @'
class Pair {
    left: i64
    right: i64
    fn total() -> i64 = self.left + self.right
}
print Pair(2, 3).total()
'@)
$classVm = & $binary run $classSource --engine vm
if ($LASTEXITCODE -ne 0 -or ($classVm -join "`n") -ne '5') { throw 'Installed class method VM failed' }
& $binary compile $classSource
if ($LASTEXITCODE -ne 0) { throw 'Installed class method native compile failed' }
$classNative = & "$classSource.exe"
if ($LASTEXITCODE -ne 0 -or ($classNative -join "`n") -ne '5') { throw 'Installed class method native execution failed' }
Remove-Item -LiteralPath $classSource, "$classSource.exe", "$classSource.win64.S"
$bitsSource = Join-Path $smokeRoot 'bits-smoke.gak'
[System.IO.File]::WriteAllText($bitsSource, "print 0xffffffffffffffff >>> 63`nprint (0xf0 & 0x3c) | 0x80`n")
$bitsVm = & $binary run $bitsSource --engine vm
if ($LASTEXITCODE -ne 0 -or ($bitsVm -join "`n") -ne "1`n176") { throw 'Installed bitwise VM failed' }
& $binary compile $bitsSource
if ($LASTEXITCODE -ne 0) { throw 'Installed bitwise native compile failed' }
$bitsNative = & "$bitsSource.exe"
if ($LASTEXITCODE -ne 0 -or ($bitsNative -join "`n") -ne "1`n176") { throw 'Installed bitwise native execution failed' }
Remove-Item -LiteralPath $bitsSource, "$bitsSource.exe", "$bitsSource.win64.S"
$matchSource = Join-Path $smokeRoot 'match-smoke.gak'
[System.IO.File]::WriteAllText($matchSource, "print match 0x5a { 0x4d => 0, 0x5a => 1, _ => 2 }`n")
$matchVm = & $binary run $matchSource --engine vm
if ($LASTEXITCODE -ne 0 -or ($matchVm -join "`n") -ne '1') { throw 'Installed match VM failed' }
& $binary compile $matchSource
if ($LASTEXITCODE -ne 0) { throw 'Installed match native compile failed' }
$matchNative = & "$matchSource.exe"
if ($LASTEXITCODE -ne 0 -or ($matchNative -join "`n") -ne '1') { throw 'Installed match native execution failed' }
Remove-Item -LiteralPath $matchSource, "$matchSource.exe", "$matchSource.win64.S"
& $binary check (Join-Path $smokeRoot 'examples\interop\main.gak')
if ($LASTEXITCODE -ne 0) { throw 'Installed interop syntax check failed' }
$groupedOutput = & $binary run (Join-Path $smokeRoot 'examples\grouped_imports.gak')
if ($LASTEXITCODE -ne 0 -or ($groupedOutput -join "`n") -ne '4d5a') {
    throw 'Installed grouped import example failed'
}
$spliceCase = Join-Path $smokeRoot 'splice-case.json'
$spliceOutput = & $binary run (Join-Path $smokeRoot 'examples\splice.gak') --engine vm --case $spliceCase
if ($LASTEXITCODE -ne 0 -or $spliceOutput.Count -ne 4 -or
    ($spliceOutput[0..2] -join "`n") -ne "4142ff004344`n414344`n41434445") {
    throw 'Installed splice example failed'
}
& $binary verify-case $spliceCase
if ($LASTEXITCODE -ne 0) { throw 'Installed splice case verification failed' }
Remove-CaseArtifact $spliceCase
$decisionOutput = & $binary run (Join-Path $smokeRoot 'examples\decision_chain.gak') --engine vm
if ($LASTEXITCODE -ne 0 -or ($decisionOutput -join "`n") -ne "critical`nhigh`nmedium`nlow`n11`n7") {
    throw 'Installed else-if decision example failed'
}
$conditionalExample = Join-Path $smokeRoot 'examples\conditional_actions.gak'
$conditionalOutput = & $binary run $conditionalExample --engine vm
if ($LASTEXITCODE -ne 0 -or ($conditionalOutput -join "`n") -ne "high`n1`n1`n0") {
    throw 'Installed conditional action example failed'
}
$conditionalCopy = Join-Path $smokeRoot 'conditional-actions.gak'
Copy-Item -LiteralPath $conditionalExample -Destination $conditionalCopy
& $binary compile $conditionalCopy
if ($LASTEXITCODE -ne 0) { throw 'Installed conditional action native compilation failed' }
$conditionalNative = "$conditionalCopy.exe"
$conditionalNativeOutput = & $conditionalNative
if ($LASTEXITCODE -ne 0 -or ($conditionalNativeOutput -join "`n") -ne "high`n1`n1`n0") {
    throw 'Installed conditional action native execution failed'
}
Remove-Item -LiteralPath $conditionalCopy, $conditionalNative, "$conditionalCopy.win64.S"
$earlyExample = Join-Path $smokeRoot 'examples\early_return.gak'
$earlyOutput = & $binary run $earlyExample --engine vm
if ($LASTEXITCODE -ne 0 -or ($earlyOutput -join "`n") -ne "critical`nreview`nlow`n3`n2`n0") {
    throw 'Installed early-return example failed'
}
$earlyCopy = Join-Path $smokeRoot 'early-return.gak'
Copy-Item -LiteralPath $earlyExample -Destination $earlyCopy
& $binary compile $earlyCopy
if ($LASTEXITCODE -ne 0) { throw 'Installed early-return native compilation failed' }
$earlyNative = "$earlyCopy.exe"
$earlyNativeOutput = & $earlyNative
if ($LASTEXITCODE -ne 0 -or ($earlyNativeOutput -join "`n") -ne "critical`nreview`nlow`n3`n2`n0") {
    throw 'Installed early-return native execution failed'
}
Remove-Item -LiteralPath $earlyCopy, $earlyNative, "$earlyCopy.win64.S"
$integerExample = Join-Path $smokeRoot 'examples\integer_boundaries.gak'
$integerOutput = & $binary run $integerExample --engine vm
if ($LASTEXITCODE -ne 0 -or $integerOutput.Count -ne 5 -or $integerOutput[0] -ne '4' -or
    -not $integerOutput[4].Contains('value: 65535')) {
    throw 'Installed integer-boundary mutation example failed'
}
$hexOutput = & $binary run (Join-Path $smokeRoot 'examples\hex_view.gak') --engine vm
if ($LASTEXITCODE -ne 0 -or $hexOutput.Count -ne 3 -or
    -not $hexOutput[0].StartsWith('00000000  47 41 4b 00') -or
    -not $hexOutput[2].EndsWith('|ABC|')) {
    throw 'Installed hexdump example failed'
}
$exhaustiveExample = Join-Path $smokeRoot 'examples\exhaustive_return.gak'
$exhaustiveOutput = & $binary run $exhaustiveExample --engine vm
if ($LASTEXITCODE -ne 0 -or ($exhaustiveOutput -join "`n") -ne "critical`nreview`nlow`n3`n-1`n0") {
    throw 'Installed exhaustive-return example failed'
}
$exhaustiveCopy = Join-Path $smokeRoot 'exhaustive-return.gak'
Copy-Item -LiteralPath $exhaustiveExample -Destination $exhaustiveCopy
& $binary compile $exhaustiveCopy
if ($LASTEXITCODE -ne 0) { throw 'Installed exhaustive-return native compilation failed' }
$exhaustiveNative = "$exhaustiveCopy.exe"
$exhaustiveNativeOutput = & $exhaustiveNative
if ($LASTEXITCODE -ne 0 -or ($exhaustiveNativeOutput -join "`n") -ne "critical`nreview`nlow`n3`n-1`n0") {
    throw 'Installed exhaustive-return native execution failed'
}
Remove-Item -LiteralPath $exhaustiveCopy, $exhaustiveNative, "$exhaustiveCopy.win64.S"
$resultExample = Join-Path $smokeRoot 'examples\result_explicit.gak'
$resultOutput = & $binary run $resultExample --engine vm
if ($LASTEXITCODE -ne 0 -or $resultOutput[0] -ne 'marker needs at least three bytes' -or
    -not $resultOutput[1].StartsWith('impact {')) {
    throw 'Installed Result<T> example failed'
}
$packageExample = Join-Path $smokeRoot 'examples\package_demo\src\main.gak'
$packageOutput = & $binary run $packageExample --engine vm
if ($LASTEXITCODE -ne 0 -or $packageOutput[0] -ne 'MZ marker' -or
    -not $packageOutput[1].StartsWith('impact {')) {
    throw 'Installed versioned transitive package example failed'
}
$missingImport = Join-Path $smokeRoot 'missing-import.gak'
[System.IO.File]::WriteAllText($missingImport, "from std.binary import absent`nprint 1`n")
$missingError = Join-Path $smokeRoot 'missing-import.err'
$missingCheck = Start-Process -FilePath $binary -ArgumentList 'check', $missingImport -Wait -PassThru -WindowStyle Hidden -RedirectStandardError $missingError
if ($missingCheck.ExitCode -eq 0 -or
    -not (Get-Content -LiteralPath $missingError -Raw).Contains('unknown imported symbol absent')) {
    throw 'Installed CLI did not reject a missing from-import'
}
$depthDir = Join-Path $smokeRoot 'depth-smoke'
New-Item -ItemType Directory -Path $depthDir | Out-Null
for ($depth = 0; $depth -le 64; $depth++) {
    $source = if ($depth -eq 64) { "fn value() -> i64 = 1`n" } else { "import m$($depth + 1)`n" }
    [System.IO.File]::WriteAllText((Join-Path $depthDir "m$depth.gak"), $source)
}
$depthError = Join-Path $smokeRoot 'depth-smoke.err'
$depthCheck = Start-Process -FilePath $binary -ArgumentList 'check', (Join-Path $depthDir 'm0.gak') -Wait -PassThru -WindowStyle Hidden -RedirectStandardError $depthError
if ($depthCheck.ExitCode -eq 0 -or
    -not (Get-Content -LiteralPath $depthError -Raw).Contains('module import depth exceeds 64')) {
    throw 'Installed CLI did not handle the module depth limit cleanly'
}
& $binary check (Join-Path $smokeRoot 'examples\delay_imports.gak')
if ($LASTEXITCODE -ne 0) { throw 'Installed CLI does not recognize delay import API' }
$python = Get-Command python -ErrorAction SilentlyContinue
if ($python) {
    $savedPythonPath = $env:PYTHONPATH
    $savedPath = $env:PATH
    try {
        $env:PYTHONPATH = Join-Path $smokeRoot 'python'
        $env:PATH = "$smokeRoot;$savedPath"
        $interopScript = Join-Path $smokeRoot 'examples\interop\main.gak'
        $interopOutput = & $binary run $interopScript --engine vm --allow-python $python.Source
        if ($LASTEXITCODE -ne 0 -or ($interopOutput -join "`n") -ne '44') {
            throw 'Installed Galeikan-to-Python interop example failed'
        }
        $interopCallerOutput = & $python.Source (Join-Path $smokeRoot 'examples\interop\caller.py')
        if ($LASTEXITCODE -ne 0 -or ($interopCallerOutput -join "`n") -ne '44') {
            throw 'Installed Python-to-Galeikan interop example failed'
        }
        $moduleOutput = & $python.Source (Join-Path $smokeRoot 'examples\python_module_view.py') $binary
        if ($LASTEXITCODE -ne 0 -or ($moduleOutput -join "`n") -ne "42`nb'GAK'") {
            throw 'Installed Python module view failed'
        }
        $sessionOutput = & $python.Source (Join-Path $smokeRoot 'examples\python_persistent_session.py') $binary
        if ($LASTEXITCODE -ne 0 -or ($sessionOutput -join "`n") -ne "42`nb'GAK'") {
            throw 'Installed persistent Galeikan session failed'
        }
        $stateOutput = & $binary run (Join-Path $smokeRoot 'examples\python_state.gak') --allow-python $python.Source
        if ($LASTEXITCODE -ne 0 -or ($stateOutput -join "`n") -ne "1`n2`n2") {
            throw 'Installed persistent Python module example failed'
        }
    } finally {
        $env:PYTHONPATH = $savedPythonPath
        $env:PATH = $savedPath
    }
}
& $binary check (Join-Path $smokeRoot 'examples\udp_probe.gak')
if ($LASTEXITCODE -ne 0) { throw 'Installed CLI does not recognize the UDP API' }
$udpNativeSource = Join-Path $smokeRoot 'native-udp-smoke.gak'
[System.IO.File]::WriteAllLines($udpNativeSource, [string[]]@(
    'requires { net.connect }',
    'from std.net import datagram',
    'from std.bytes import from_hex, repeat',
    'print datagram("127.0.0.1", 9, repeat(from_hex("01"), 65508), 1, 100)'
), $utf8NoBom)
& $binary compile $udpNativeSource
if ($LASTEXITCODE -ne 0) { throw 'Installed native UDP compilation failed' }
$udpStdout = Join-Path $smokeRoot 'native-udp-stdout.txt'
$udpStderr = Join-Path $smokeRoot 'native-udp-stderr.txt'
$udpProcess = Start-Process -FilePath "$udpNativeSource.exe" -ArgumentList @('--allow-connect', '127.0.0.1:9') -WindowStyle Hidden -Wait -PassThru -RedirectStandardOutput $udpStdout -RedirectStandardError $udpStderr
if ($udpProcess.ExitCode -eq 0 -or (Get-Content -LiteralPath $udpStderr -Raw) -notlike '*request exceeds 65507 bytes*') {
    throw 'Installed native UDP request limit was not enforced'
}
Remove-SmokeFiles -Paths @($udpNativeSource, "$udpNativeSource.exe", "$udpNativeSource.win64.S", "$udpNativeSource.native_file.c", "$udpNativeSource.native_net.c", $udpStdout, $udpStderr)
& $binary check (Join-Path $smokeRoot 'examples\http_fetch.gak')
if ($LASTEXITCODE -ne 0) { throw 'Installed CLI does not recognize the HTTP API' }
& $binary check (Join-Path $smokeRoot 'examples\http_request.gak')
if ($LASTEXITCODE -ne 0) { throw 'Installed CLI does not recognize typed HTTP requests' }
& $binary check (Join-Path $smokeRoot 'examples\http_module\main.gak')
if ($LASTEXITCODE -ne 0) { throw 'Installed CLI does not recognize module effects' }
& $binary check (Join-Path $smokeRoot 'examples\process_snapshot.gak')
if ($LASTEXITCODE -ne 0) { throw 'Installed CLI does not recognize process.snapshot' }
& $binary check (Join-Path $smokeRoot 'examples\process_regions.gak')
if ($LASTEXITCODE -ne 0) { throw 'Installed CLI does not recognize process.regions' }
& $binary check (Join-Path $smokeRoot 'examples\process_images.gak')
if ($LASTEXITCODE -ne 0) { throw 'Installed CLI does not recognize process.images' }
$profileExample = Join-Path $smokeRoot 'examples\binary_profile.gak'
& $binary check $profileExample
if ($LASTEXITCODE -ne 0) { throw 'Installed CLI does not recognize binary profile API' }
$profileOutput = & $binary run $profileExample --allow-read 'C:\Windows\System32' -- 'C:\Windows\System32\notepad.exe'
$profileHeader = ($profileOutput | Select-Object -First 4) -join "`n"
if ($LASTEXITCODE -ne 0 -or $profileHeader -ne "pe`n64`nlittle`nx86_64") {
    throw 'Installed binary profile example failed'
}
$modulesExample = Join-Path $smokeRoot 'examples\process_modules.gak'
& $binary check $modulesExample
if ($LASTEXITCODE -ne 0) { throw 'Installed CLI does not recognize process.modules' }
$moduleOutput = & $binary run $modulesExample --allow-process "$PID" -- "$PID"
if ($LASTEXITCODE -ne 0 -or $moduleOutput.Count -lt 2 -or [int]$moduleOutput[0] -ne ($moduleOutput.Count - 1)) {
    throw 'Installed process.modules example failed'
}
$addressSource = Join-Path $smokeRoot 'process-address-smoke.gak'
[System.IO.File]::WriteAllText($addressSource, "requires { process.inspect }`nfrom std.process import images, at, start, locate, offset, address`nlet maps = images($PID)`nlet region = at(maps, 0)`nlet base = start(region)`nprint address(locate(maps, base), offset(region, base)) == base`n")
$addressOutput = & $binary run $addressSource --allow-process "$PID"
if ($LASTEXITCODE -ne 0 -or ($addressOutput -join "`n") -ne 'true') { throw 'Installed process address API failed' }
Remove-Item -LiteralPath $addressSource
$signalsExample = Join-Path $smokeRoot 'examples\hardening_signals.gak'
$signalsOutput = & $binary run $signalsExample --allow-read 'C:\Windows\System32' -- 'C:\Windows\System32\notepad.exe'
if ($LASTEXITCODE -ne 0 -or
    -not (($signalsOutput -join "`n").Contains("pe.dynamic_base`n")) -or
    -not (($signalsOutput -join "`n").Contains("elf.et_dyn`nnot_applicable")) -or
    -not (($signalsOutput -join "`n").Contains("elf.bind_now`nnot_applicable")) -or
    -not (($signalsOutput -join "`n").Contains("elf.relro_now`nnot_applicable"))) {
    throw 'Installed CLI format signal inspection failed'
}
$nativeFormatSource = Join-Path $smokeRoot 'native-format-smoke.gak'
[System.IO.File]::WriteAllLines($nativeFormatSource, [string[]]@(
    'requires { file.read }',
    'from std.binary import analyze',
    'from std.formats import probe, kind, bits, signal',
    'from std.cli import arg',
    'let report: Format = probe(analyze(arg(0), 67108864))',
    'print kind(report)',
    'print bits(report)',
    'print signal(report, "pe.nx_compat")'
), $utf8NoBom)
& $binary compile $nativeFormatSource
if ($LASTEXITCODE -ne 0) { throw 'Installed CLI native format compilation failed' }
$nativeFormatOutput = & "$nativeFormatSource.exe" --allow-read 'C:\Windows\System32' -- 'C:\Windows\System32\notepad.exe'
if ($LASTEXITCODE -ne 0 -or ($nativeFormatOutput -join "`n") -ne "pe`n64`npresent") {
    throw 'Installed native PE format inspection failed'
}
Remove-Item -LiteralPath $nativeFormatSource, "$nativeFormatSource.exe", "$nativeFormatSource.win64.S", "$nativeFormatSource.native_file.c", "$nativeFormatSource.native_formats.c"
$wxExample = Join-Path $smokeRoot 'examples\section_wx.gak'
$wxCase = Join-Path $smokeRoot 'section-wx-case.json'
& $binary run $wxExample --allow-read $smokeRoot --case $wxCase -- $binary
if ($LASTEXITCODE -ne 0) { throw 'Installed section W+X audit failed' }
$wxDocument = Get-Content -LiteralPath $wxCase -Raw -Encoding utf8 | ConvertFrom-Json
if ($wxDocument.events[-1].value.kind -ne 'signal' -or
    $wxDocument.events[-1].value.signal -ne 'pe.section_wx') {
    throw 'Installed section W+X case output is invalid'
}
& $binary verify-case $wxCase
if ($LASTEXITCODE -ne 0) { throw 'Installed section W+X case verification failed' }
Remove-CaseArtifact $wxCase
$signalAudit = Join-Path $smokeRoot 'examples\hardening_audit.gak'
$signalCase = Join-Path $smokeRoot 'signal-case.json'
& $binary run $signalAudit --allow-read 'C:\Windows\System32' --case $signalCase -- 'C:\Windows\System32\notepad.exe'
if ($LASTEXITCODE -ne 0) { throw 'Installed CLI signal audit failed' }
$signalDocument = Get-Content -LiteralPath $signalCase -Raw -Encoding utf8 | ConvertFrom-Json
if ($signalDocument.events[0].value.kind -ne 'signal' -or
    $signalDocument.events[0].value.signal -ne 'pe.nx_compat') {
    throw 'Installed CLI signal case output is invalid'
}
& $binary verify-case $signalCase
if ($LASTEXITCODE -ne 0) { throw 'Installed CLI signal case verification failed' }
Remove-CaseArtifact $signalCase
$auditExample = Join-Path $smokeRoot 'examples\audit_hunt.gak'
& $binary check $auditExample
if ($LASTEXITCODE -ne 0) { throw 'Installed CLI does not recognize audit.hunt' }
$auditFixture = Join-Path $smokeRoot 'audit-sample.bin'
$auditCase = Join-Path $smokeRoot 'audit-case.json'
[System.IO.File]::WriteAllBytes($auditFixture, [byte[]](0x4d, 0x5a, 0x00, 0x4d, 0x5a))
& $binary run $auditExample --allow-read $smokeRoot --case $auditCase -- $auditFixture
if ($LASTEXITCODE -ne 0) { throw 'Installed audit.hunt execution failed' }
$auditDocument = Get-Content -LiteralPath $auditCase -Raw -Encoding utf8 | ConvertFrom-Json
if ($auditDocument.events[0].value.kind -ne 'pattern' -or
    $auditDocument.events[0].value.count -ne 2) {
    throw 'Installed audit.hunt case output is invalid'
}
& $binary verify-case $auditCase
if ($LASTEXITCODE -ne 0) { throw 'Installed CLI audit case verification failed' }
Remove-Item -LiteralPath $auditFixture
Remove-CaseArtifact $auditCase
$packedExample = Join-Path $smokeRoot 'examples\packed_fields.gak'
& $binary check $packedExample
if ($LASTEXITCODE -ne 0) { throw 'Installed CLI does not recognize bytes.pack' }
$packedOutput = & $binary run $packedExample
if ($LASTEXITCODE -ne 0 -or ($packedOutput -join "`n") -ne "123478563412`n4660`n305419896") {
    throw 'Installed bytes.pack roundtrip failed'
}
$rangeExample = Join-Path $smokeRoot 'examples\native_range.gak'
& $binary check $rangeExample
if ($LASTEXITCODE -ne 0) { throw 'Installed CLI does not recognize range loops' }
$rangeCopy = Join-Path $smokeRoot 'native-range.gak'
Copy-Item -LiteralPath $rangeExample -Destination $rangeCopy
& $binary compile $rangeCopy
if ($LASTEXITCODE -ne 0) { throw 'Installed native range compilation failed' }
$rangeExecutable = "$rangeCopy.exe"
$rangeOutput = & $rangeExecutable
if ($LASTEXITCODE -ne 0 -or ($rangeOutput -join "`n") -ne '6') {
    throw 'Installed native range execution failed'
}
Remove-Item -LiteralPath $rangeCopy, $rangeExecutable, "$rangeCopy.win64.S"
$python = Get-Command python -ErrorAction SilentlyContinue
if ($python) {
    $pythonHelper = Join-Path $smokeRoot 'native-python-helper.py'
    $pythonSource = Join-Path $smokeRoot 'native-python-smoke.gak'
    [System.IO.File]::WriteAllLines($pythonHelper, [string[]]@('def double(values):', '    return [value * 2 for value in values]'), $utf8NoBom)
    [System.IO.File]::WriteAllLines($pythonSource, [string[]]@(
        'requires { python.exec }',
        'import "py:native-python-helper.py" as helper',
        'from std.text import length, slice',
        'fn double(value: i64) -> i64 = value * 2',
        'let answers: List<i64> = helper.double([20, 21])',
        'print answers[0]',
        'print answers[1]',
        'print "Galeikan" + "Script"',
        'print length("Galeikan")',
        'print slice("Galeikan", 1, 2) == "al"'
    ), $utf8NoBom)
    & $binary compile $pythonSource
    if ($LASTEXITCODE -ne 0) { throw 'Installed native Python compilation failed' }
    $pythonOutput = & "$pythonSource.exe" --allow-python $python.Source
    if ($LASTEXITCODE -ne 0 -or ($pythonOutput -join "`n") -ne "40`n42`nGaleikanScript`n8`ntrue") {
        throw 'Installed native Python bridge failed'
    }
    $savedPythonPath = $env:PYTHONPATH
    try {
        $env:PYTHONPATH = Join-Path $smokeRoot 'python'
        $reverseOutput = & $python.Source -c 'from galeikan_bridge import Galeikan; import sys; print(Galeikan(sys.argv[1]).module(sys.argv[2], allow_python=sys.argv[3]).double(21))' $binary "$pythonSource.exe" $python.Source
        if ($LASTEXITCODE -ne 0 -or ($reverseOutput -join "`n") -ne '42') {
            throw 'Installed Python-to-native Galeikan bridge failed'
        }
    } finally {
        $env:PYTHONPATH = $savedPythonPath
    }
    Remove-SmokeFiles -Paths @($pythonHelper, $pythonSource, "$pythonSource.exe", "$pythonSource.win64.S", "$pythonSource.native_file.c", "$pythonSource.native_python.c", "$pythonSource.native_text.c")
}
$processSource = Join-Path $smokeRoot 'native-process-smoke.gak'
[System.IO.File]::WriteAllLines($processSource, [string[]]@(
    'requires { process.inspect }',
    'import std.process',
    'from std.result import is_error',
    'from std.list import count',
    'fn checked() -> Result<Source> {',
    '    let source: Source = process.snapshot(process.self_pid(), 1, 4)',
    '    return source',
    '}',
    'print process.self_pid()',
    'print is_error(checked())',
    'print count(process.modules(process.self_pid())) > 0',
    'print process.parent_pid(process.self_pid()) > 0',
    'print count(process.children(process.self_pid())) == 0'
), $utf8NoBom)
& $binary compile $processSource
if ($LASTEXITCODE -ne 0) { throw 'Installed native process compilation failed' }
$processOutput = & "$processSource.exe" --allow-process self
if ($LASTEXITCODE -ne 0 -or $processOutput.Count -ne 5 -or $processOutput[0] -notmatch '^[1-9][0-9]*$' -or $processOutput[1] -ne 'true' -or $processOutput[2] -ne 'true' -or $processOutput[3] -ne 'true' -or $processOutput[4] -ne 'true') {
    throw 'Installed native process bridge failed'
}
Remove-Item -LiteralPath $processSource, "$processSource.exe", "$processSource.win64.S", "$processSource.native_file.c"
& $binary run $example
if ($LASTEXITCODE -ne 0) { throw 'Installed CLI run failed' }
$caseExample = Join-Path $smokeRoot 'examples\case_lineage.gak'
$caseOutput = Join-Path $smokeRoot 'case-report.json'
& $binary run $caseExample --case $caseOutput
if ($LASTEXITCODE -ne 0) { throw 'Installed CLI case export failed' }
$caseDocument = Get-Content -LiteralPath $caseOutput -Raw -Encoding utf8 | ConvertFrom-Json
if ($caseDocument.format -ne 'galeikan.case' -or $caseDocument.events.Count -ne 2 -or $caseDocument.events[0].value.source_lineage.Count -ne 4) {
    throw 'Installed CLI case format is invalid'
}
& $binary verify-case $caseOutput
if ($LASTEXITCODE -ne 0) { throw 'Installed CLI lineage case verification failed' }
Remove-CaseArtifact $caseOutput
for ($depth = 0; $depth -le 64; $depth++) {
    Remove-Item -LiteralPath (Join-Path $depthDir "m$depth.gak")
}
Remove-Item -LiteralPath $depthDir, $depthError, $missingImport, $missingError
Get-ChildItem -LiteralPath $smokeRoot -Filter '*.native_call.c' -File |
    ForEach-Object { Remove-Item -LiteralPath $_.FullName }

$uninstaller = Join-Path $smokeRoot 'Uninstall.exe'
$uninstall = Start-Process -FilePath $uninstaller -ArgumentList '/S' -Wait -PassThru -WindowStyle Hidden
if ($uninstall.ExitCode -ne 0) { throw "Silent uninstall failed with exit code $($uninstall.ExitCode)" }
if (Test-Path -LiteralPath $smokeRoot) {
    $remaining = @(Get-ChildItem -LiteralPath $smokeRoot -Force)
    if ($remaining.Count -eq 1 -and $remaining[0].Name -eq 'Uninstall.exe') {
        $retry = Start-Process -FilePath $uninstaller -ArgumentList '/S' -Wait -PassThru -WindowStyle Hidden
        if ($retry.ExitCode -ne 0) { throw "Silent uninstall retry failed with exit code $($retry.ExitCode)" }
    }
}
if (Test-Path -LiteralPath $smokeRoot) { throw "Uninstaller left files in $smokeRoot" }
$registryEnvironment = [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey('Environment')
$uninstalledUserPath = $registryEnvironment.GetValue('Path', '', [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
$registryEnvironment.Dispose()
if ($uninstalledUserPath -cne $originalUserPath) { throw 'Uninstaller did not restore the user PATH' }
if ((Test-Path -LiteralPath 'Registry::HKEY_CURRENT_USER\Software\Classes\Galeikan.Lang') -or
    (Test-Path -LiteralPath 'Registry::HKEY_CURRENT_USER\Software\Classes\Galeikan.Script') -or
    (Test-Path -LiteralPath 'Registry::HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Uninstall\Galeikan')) {
    throw 'Uninstaller left Galeikan file type registrations'
}
Write-Output 'Windows install, CLI smoke test and uninstall passed.'
