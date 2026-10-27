$ErrorActionPreference = 'Stop'
$helper = Join-Path (Resolve-Path (Join-Path $PSScriptRoot '..')).Path 'dist\galeikan-path.exe'
if (-not (Test-Path -LiteralPath $helper)) { throw "Missing PATH helper: $helper" }

$environment = [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey('Environment', $true)
if (-not $environment) { throw 'Cannot open the user environment registry key' }
$owner = [Microsoft.Win32.Registry]::CurrentUser.CreateSubKey('Software\Galeikan\Installer')
$original = $environment.GetValue('Path', $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
$originalKind = if ($null -ne $original) { $environment.GetValueKind('Path') } else { $null }
$priorMarker = $owner.GetValue('PathEntry', $null)
$target = Join-Path $env:TEMP "Galeikan Path Smoke $PID"
if ($original -and $original.Contains($target)) { throw 'Smoke path is already present' }
if ($priorMarker) { throw 'Installer PATH marker already exists; test refuses to disturb it' }

try {
    $result = Start-Process -FilePath $helper -ArgumentList ('add "{0}"' -f $target) -Wait -PassThru -WindowStyle Hidden
    if ($result.ExitCode -ne 0) { throw "PATH add returned $($result.ExitCode)" }
    $once = $environment.GetValue('Path', '', [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
    if (-not $once.EndsWith(";$target") -and $once -ne $target) { throw 'PATH add did not append the installation directory' }

    $result = Start-Process -FilePath $helper -ArgumentList ('add "{0}"' -f $target) -Wait -PassThru -WindowStyle Hidden
    if ($result.ExitCode -ne 0) { throw "Repeated PATH add returned $($result.ExitCode)" }
    $twice = $environment.GetValue('Path', '', [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
    if ($twice -cne $once) { throw 'Repeated installation duplicated or changed PATH' }

    $result = Start-Process -FilePath $helper -ArgumentList ('remove "{0}"' -f $target) -Wait -PassThru -WindowStyle Hidden
    if ($result.ExitCode -ne 0) { throw "PATH remove returned $($result.ExitCode)" }
    $after = $environment.GetValue('Path', '', [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
    if ($after -cne [string]$original) { throw 'Uninstall did not restore the original PATH' }
    if ($owner.GetValue('PathEntry', $null)) { throw 'Uninstall left its PATH ownership marker' }

    $preexisting = if ($original) { "$original;$target" } else { $target }
    $environment.SetValue('Path', $preexisting, [Microsoft.Win32.RegistryValueKind]::ExpandString)
    $result = Start-Process -FilePath $helper -ArgumentList ('add "{0}"' -f $target) -Wait -PassThru -WindowStyle Hidden
    if ($result.ExitCode -ne 0) { throw "Pre-existing PATH add returned $($result.ExitCode)" }
    $result = Start-Process -FilePath $helper -ArgumentList ('remove "{0}"' -f $target) -Wait -PassThru -WindowStyle Hidden
    if ($result.ExitCode -ne 0) { throw "Pre-existing PATH remove returned $($result.ExitCode)" }
    if ($environment.GetValue('Path', '', [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames) -cne $preexisting) {
        throw 'Uninstall removed a pre-existing user-owned PATH entry'
    }
    Write-Host 'Windows PATH helper add, reinstall, uninstall, and user-owned entry checks passed.'
} finally {
    if ($null -eq $original) { $environment.DeleteValue('Path', $false) }
    else { $environment.SetValue('Path', $original, $originalKind) }
    if ($priorMarker) { $owner.SetValue('PathEntry', $priorMarker, [Microsoft.Win32.RegistryValueKind]::String) }
    else { $owner.DeleteValue('PathEntry', $false) }
    $owner.Dispose()
    $environment.Dispose()
}
