param(
    [string]$VersionsDir = (Join-Path $PSScriptRoot '..\..\..\stellaris_versions'),
    [switch]$Publish
)
$ErrorActionPreference = 'Stop'
$taskRoot = Split-Path $PSScriptRoot -Parent
$taskOut = Join-Path $taskRoot 'build\compatibility'
$taskScan = Join-Path $PSScriptRoot 'build_test\scan_test.exe'
$taskDll = Join-Path $taskRoot 'build\achievement_unlocker.dll'
New-Item -ItemType Directory -Force $taskOut | Out-Null

function Get-Sha256([string]$Path) {
    $taskHash = [Security.Cryptography.SHA256]::Create()
    $taskStream = [IO.File]::OpenRead($Path)
    try { [BitConverter]::ToString($taskHash.ComputeHash($taskStream)).Replace('-', '').ToLowerInvariant() }
    finally { $taskStream.Dispose(); $taskHash.Dispose() }
}

$taskFiles = @(Get-ChildItem -LiteralPath $VersionsDir -Filter 'stellaris_*.exe' |
    Where-Object Name -NotLike 'stellaris_3.14.*' | Sort-Object Name)
if (!$taskFiles.Count) { throw "No target executables in $VersionsDir" }
$taskResults = @()
$taskLogs = @('Offline checks only; no game launch or backend achievement verification.', '')
foreach ($taskFile in $taskFiles) {
    $taskLines = @(& $taskScan $taskFile.FullName)
    $taskExit = $LASTEXITCODE
    $taskLines | Set-Content -Encoding UTF8 (Join-Path $taskOut ($taskFile.BaseName + '.txt'))
    $taskLogs += $taskLines
    $taskLogs += ''
    $taskResults += [ordered]@{
        file = $taskFile.Name
        sha256 = Get-Sha256 $taskFile.FullName
        exit_code = $taskExit
        passed = ($taskExit -eq 0 -and $taskLines[-1] -eq 'OK')
        patch_sites = @($taskLines | Select-Object -Skip 4 -First 8)
        manager = @($taskLines | Select-Object -Skip 12 -First 2)
        hook = @($taskLines | Select-Object -Skip 14 -First 1)
    }
    Write-Host ($taskFile.Name + ': ' + $taskLines[-1])
}
$taskPassed = @($taskResults | Where-Object { !$_.passed }).Count -eq 0
[ordered]@{
    build = 'r9.2 2026-11-19'
    dll_sha256 = Get-Sha256 $taskDll
    scan_test_sha256 = Get-Sha256 $taskScan
    excluded = '3.14.*'
    test_scope = 'Offline mapped-image dry run, writes, idempotency, cosmetic opt-out, four drift checks, old-save repair hook locator'
    in_game_tested_this_revision = $false
    in_game_probe_note = 'r9: injected into Stellaris 4.5.4 (Cygnus) and reached the main menu. The old-save repair hook reported hooked (Update 0x5B2D60, OnGameStart 0x5B30D0, call 0x2600C3) and the process ran without error. No save was loaded, so neither the rebuild nor the Steam backend was exercised.'
    passed = $taskPassed
    versions = $taskResults
} | ConvertTo-Json -Depth 6 | Set-Content -Encoding UTF8 (Join-Path $taskOut 'validation.json')
$taskLogs | Set-Content -Encoding UTF8 (Join-Path $taskOut 'scan_logs.txt')
if (!$taskPassed) { throw 'Compatibility check failed; release unchanged.' }
if ($Publish) {
    $taskRelease = Join-Path $taskRoot '..\..\full_releases\achievement_unlocker_dll'
    Copy-Item -LiteralPath $taskDll -Destination (Join-Path $taskRelease 'achievement_unlocker.dll') -Force
    Copy-Item -LiteralPath (Join-Path $taskOut 'validation.json') -Destination $taskRelease -Force
    Copy-Item -LiteralPath (Join-Path $taskOut 'scan_logs.txt') -Destination (Join-Path $taskRelease '验证记录_离线扫描.txt') -Force
}
