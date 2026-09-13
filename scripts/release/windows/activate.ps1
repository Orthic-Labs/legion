param(
  [Parameter(Mandatory=$true)][string]$InstallRoot,
  [Parameter(Mandatory=$true)][string]$Version,
  [ValidateRange(1, 600)][int]$ChildTimeoutSeconds = 60
)
$ErrorActionPreference = 'Stop'
$rootPath = [IO.Path]::GetFullPath($InstallRoot).TrimEnd('\')
if ($Version -notmatch '^\d+\.\d+\.\d+$') { throw 'Invalid Legion version' }
$currentPath = Join-Path $rootPath 'current'
$versionPath = Join-Path $rootPath ('versions\' + $Version)
$backupPath = Join-Path $rootPath ('.previous-current-' + [Guid]::NewGuid().ToString('N'))
$stagePath = Join-Path $rootPath ('.next-current-' + [Guid]::NewGuid().ToString('N'))
$eventLog = if ($env:LEGION_INSTALL_EVENT_LOG) { [IO.Path]::GetFullPath($env:LEGION_INSTALL_EVENT_LOG) } else { Join-Path $rootPath 'install-events.jsonl' }
if ($env:LEGION_INSTALL_CHILD_TIMEOUT_SECONDS -match '^\d+$') {
  $ChildTimeoutSeconds = [Math]::Max(1, [Math]::Min(600, [int]$env:LEGION_INSTALL_CHILD_TIMEOUT_SECONDS))
}
foreach ($path in @($currentPath, $versionPath, $backupPath, $stagePath)) {
  if (-not [IO.Path]::GetFullPath($path).StartsWith($rootPath + '\', [StringComparison]::OrdinalIgnoreCase)) { throw 'Activation path escaped install root' }
}
if (-not [IO.Path]::IsPathRooted($eventLog)) { throw 'Activation event log must be absolute' }
$eventDirectory = Split-Path -Parent $eventLog
if ($eventDirectory) { New-Item -ItemType Directory -Path $eventDirectory -Force | Out-Null }
function Write-InstallEvent([string]$Stage, [string]$Status, [string]$Detail = '') {
  [ordered]@{schema='legion.install.event.v1';timestamp=[DateTime]::UtcNow.ToString('o');stage=$Stage;status=$Status;detail=$Detail} |
    ConvertTo-Json -Compress | Add-Content -LiteralPath $eventLog -Encoding UTF8
}
function Stop-ProcessTree([int]$ProcessId) {
  try { & taskkill.exe /PID $ProcessId /T /F 2>$null | Out-Null } catch { }
}
function Sync-PackagedLocalCacheMirrors([string]$CurrentPath) {
  $localAppData = [Environment]::GetFolderPath('LocalApplicationData')
  $packagesRoot = Join-Path $localAppData 'Packages'
  if (-not (Test-Path -LiteralPath $packagesRoot -PathType Container)) { return }
  foreach ($package in Get-ChildItem -LiteralPath $packagesRoot -Directory -ErrorAction SilentlyContinue) {
    $mirrorProductRoot = Join-Path $package.FullName 'LocalCache\Local\Orthic Labs\Legion'
    if (-not (Test-Path -LiteralPath $mirrorProductRoot -PathType Container)) { continue }
    $mirrorCurrent = Join-Path $mirrorProductRoot 'current'
    $stagePath = Join-Path $mirrorProductRoot ('.next-current-' + [Guid]::NewGuid().ToString('N'))
    try {
      Write-InstallEvent 'localcache-mirror' 'started' $mirrorCurrent
      Copy-Item -LiteralPath $CurrentPath -Destination $stagePath -Recurse
      if (Test-Path -LiteralPath $mirrorCurrent) { Remove-Item -LiteralPath $mirrorCurrent -Recurse -Force }
      Move-Item -LiteralPath $stagePath -Destination $mirrorCurrent
      Write-InstallEvent 'localcache-mirror' 'complete' $mirrorCurrent
    } catch {
      Remove-Item -LiteralPath $stagePath -Recurse -Force -ErrorAction SilentlyContinue
      Write-InstallEvent 'localcache-mirror' 'failed' ($_ | Out-String).Trim()
    }
  }
}
function Invoke-Bounded([string]$Stage, [string]$FilePath, [string[]]$Arguments) {
  if ($Arguments | Where-Object { $_ -match '"' }) { throw "$Stage argument contains unsupported quote" }
  $argumentLine = ($Arguments | ForEach-Object { if ($_ -match '\s') { '"' + $_ + '"' } else { $_ } }) -join ' '
  $startInfo = [Diagnostics.ProcessStartInfo]::new()
  $startInfo.FileName = $FilePath
  $startInfo.Arguments = $argumentLine
  $startInfo.UseShellExecute = $false
  $startInfo.CreateNoWindow = $true
  $startInfo.RedirectStandardOutput = $true
  $startInfo.RedirectStandardError = $true
  $process = [Diagnostics.Process]::new()
  $process.StartInfo = $startInfo
  try {
    Write-InstallEvent $Stage 'started' "timeout=${ChildTimeoutSeconds}s"
    if (-not $process.Start()) { throw "$Stage failed to start" }
    $stdoutTask = $process.StandardOutput.ReadToEndAsync()
    $stderrTask = $process.StandardError.ReadToEndAsync()
    if (-not $process.WaitForExit($ChildTimeoutSeconds * 1000)) {
      Stop-ProcessTree $process.Id
      Write-InstallEvent $Stage 'failed' "timeout=${ChildTimeoutSeconds}s"
      throw "$Stage timed out after ${ChildTimeoutSeconds}s"
    }
    $exitCode = $process.ExitCode
    $drainTimeoutMs = [Math]::Min(5000, $ChildTimeoutSeconds * 1000)
    if (-not [Threading.Tasks.Task]::WaitAll([Threading.Tasks.Task[]]@($stdoutTask, $stderrTask), $drainTimeoutMs)) {
      $process.StandardOutput.Dispose()
      $process.StandardError.Dispose()
      Write-InstallEvent $Stage 'failed' "output-drain-timeout=${drainTimeoutMs}ms"
      throw "$Stage output drain timed out after ${drainTimeoutMs}ms"
    }
    $stdout = [string]$stdoutTask.GetAwaiter().GetResult()
    $stderr = [string]$stderrTask.GetAwaiter().GetResult()
    if ($exitCode -ne 0) {
      Write-InstallEvent $Stage 'failed' "exit=$exitCode; stdout=$(([string]$stdout).Trim()); stderr=$(([string]$stderr).Trim())"
      throw "$Stage exited $exitCode"
    }
    Write-InstallEvent $Stage 'complete' 'exit=0'
    return $stdout
  } finally {
    $process.Dispose()
  }
}
if (-not (Test-Path -LiteralPath (Join-Path $versionPath 'bin\legion.exe') -PathType Leaf)) { throw 'Installed Legion executable missing' }
$hadCurrent = $null -ne (Get-Item -LiteralPath $currentPath -Force -ErrorAction SilentlyContinue)
Write-InstallEvent 'activation' 'started' "version=$Version"
if ($hadCurrent) { Move-Item -LiteralPath $currentPath -Destination $backupPath }
try {
  Copy-Item -LiteralPath $versionPath -Destination $stagePath -Recurse
  Move-Item -LiteralPath $stagePath -Destination $currentPath
  $legion = Join-Path $currentPath 'bin\legion.exe'
  $reportedVersion = ([string](Invoke-Bounded 'activation-version' $legion @('--version'))).Trim()
  if ($reportedVersion -ne $Version) { throw "Activation verification returned version $reportedVersion" }
  if ($env:LEGION_INSTALL_TEST_MODE -eq 'refresh-failure') { throw 'Forced client refresh failure' }
  if ($env:LEGION_INSTALL_TEST_MODE -eq 'stalled-child') {
    Invoke-Bounded 'client-refresh' "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" @('-NoProfile','-NonInteractive','-Command','Start-Sleep -Seconds 30') | Out-Null
  } else {
    $refreshJson = Invoke-Bounded 'client-refresh' $legion @('--json','setup','repair','--confirm')
    try { $refresh = $refreshJson | ConvertFrom-Json -ErrorAction Stop } catch { throw 'Client refresh returned invalid JSON' }
    if ($refresh.status -ne 'complete') { throw "Client refresh status=$($refresh.status)" }
  }
  Remove-Item -LiteralPath $backupPath -Recurse -Force -ErrorAction SilentlyContinue
  [ordered]@{schema='legion.install.activation.v1';state='activated';current=$currentPath;target=$versionPath;previous=$null;refresh='complete'} | ConvertTo-Json -Compress | Set-Content -LiteralPath (Join-Path $rootPath 'activation.json') -Encoding UTF8
  Sync-PackagedLocalCacheMirrors $currentPath
  Write-InstallEvent 'activation' 'complete' "version=$Version"
} catch {
  Remove-Item -LiteralPath $stagePath,$currentPath -Recurse -Force -ErrorAction SilentlyContinue
  if ($hadCurrent -and (Test-Path -LiteralPath $backupPath)) { Move-Item -LiteralPath $backupPath -Destination $currentPath }
  Write-InstallEvent 'activation' 'failed' ($_ | Out-String).Trim()
  Write-InstallEvent 'rollback' 'complete' $(if ($hadCurrent) { 'previous current restored' } else { 'new current removed' })
  throw
}
