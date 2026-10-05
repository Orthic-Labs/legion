param(
  [Parameter(Mandatory=$true)][string]$InstallRoot,
  [Parameter(Mandatory=$true)][string]$Version,
  [ValidateRange(1, 600)][int]$ChildTimeoutSeconds = 180
)
$ErrorActionPreference = 'Stop'
$rootPath = [IO.Path]::GetFullPath($InstallRoot).TrimEnd('\')
if ($Version -notmatch '^\d+\.\d+\.\d+$') { throw 'Invalid Legion version' }
$currentPath = Join-Path $rootPath 'current'
$versionPath = Join-Path $rootPath ('versions\' + $Version)
$payloadPath = Join-Path $rootPath ('.next-version-' + $Version)
$backupPath = Join-Path $rootPath ('.previous-current-' + [Guid]::NewGuid().ToString('N'))
$versionBackupPath = Join-Path $rootPath ('.previous-version-' + [Guid]::NewGuid().ToString('N'))
$stagePath = Join-Path $rootPath ('.next-current-' + [Guid]::NewGuid().ToString('N'))
$eventLog = if ($env:LEGION_INSTALL_EVENT_LOG) { [IO.Path]::GetFullPath($env:LEGION_INSTALL_EVENT_LOG) } else { Join-Path $rootPath 'install-events.jsonl' }
if ($env:LEGION_INSTALL_CHILD_TIMEOUT_SECONDS -match '^\d+$') {
  $ChildTimeoutSeconds = [Math]::Max(1, [Math]::Min(600, [int]$env:LEGION_INSTALL_CHILD_TIMEOUT_SECONDS))
}
foreach ($path in @($currentPath, $versionPath, $payloadPath, $backupPath, $versionBackupPath, $stagePath)) {
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
function Get-BinaryHash([string]$Path) {
  $stream = [IO.File]::OpenRead($Path)
  $hasher = [Security.Cryptography.SHA256]::Create()
  try { return [BitConverter]::ToString($hasher.ComputeHash($stream)).Replace('-', '') }
  finally { $hasher.Dispose(); $stream.Dispose() }
}
function Sync-PackagedLocalCacheMirrors([string]$VersionPath, [System.Collections.Generic.List[object]]$Transactions) {
  $localAppData = [Environment]::GetFolderPath('LocalApplicationData')
  $packagesRoot = if ($env:LEGION_INSTALL_PACKAGES_ROOT) { [IO.Path]::GetFullPath($env:LEGION_INSTALL_PACKAGES_ROOT) } else { Join-Path $localAppData 'Packages' }
  if (-not (Test-Path -LiteralPath $packagesRoot -PathType Container)) { return }
  foreach ($package in Get-ChildItem -LiteralPath $packagesRoot -Directory -ErrorAction SilentlyContinue) {
    $mirrorProductRoot = Join-Path $package.FullName 'LocalCache\Local\Orthic Labs\Legion'
    if (-not (Test-Path -LiteralPath $mirrorProductRoot -PathType Container)) { continue }
    $mirrorCurrent = Join-Path $mirrorProductRoot 'current'
    $stagePath = Join-Path $mirrorProductRoot ('.next-current-' + [Guid]::NewGuid().ToString('N'))
    $backupPath = Join-Path $mirrorProductRoot ('.previous-current-' + [Guid]::NewGuid().ToString('N'))
    $transaction = [pscustomobject]@{current=$mirrorCurrent;stage=$stagePath;backup=$backupPath;backupCreated=$false;replacementCreated=$false}
    $Transactions.Add($transaction) | Out-Null
    try {
      Write-InstallEvent 'localcache-mirror' 'started' $mirrorCurrent
      Copy-Item -LiteralPath $VersionPath -Destination $stagePath -Recurse
      $sourceHash = Get-BinaryHash (Join-Path $VersionPath 'bin\legion.exe')
      $stageHash = Get-BinaryHash (Join-Path $stagePath 'bin\legion.exe')
      if ($sourceHash -ne $stageHash) { throw "Packaged LocalCache mirror stage hash mismatch: $stageHash != $sourceHash" }
      if (Test-Path -LiteralPath $mirrorCurrent) {
        Move-Item -LiteralPath $mirrorCurrent -Destination $backupPath
        $transaction.backupCreated = $true
      }
      Move-Item -LiteralPath $stagePath -Destination $mirrorCurrent
      $transaction.replacementCreated = $true
      if ($env:LEGION_INSTALL_TEST_MODE -eq 'mirror-sync-failure') { throw 'Forced packaged LocalCache mirror failure' }
      Write-InstallEvent 'localcache-mirror' 'complete' $mirrorCurrent
    } catch {
      Write-InstallEvent 'localcache-mirror' 'failed' ($_ | Out-String).Trim()
      throw
    }
  }
}
function Restore-PackagedLocalCacheMirrors([System.Collections.Generic.List[object]]$Transactions) {
  for ($index = $Transactions.Count - 1; $index -ge 0; $index--) {
    $transaction = $Transactions[$index]
    if ($transaction.replacementCreated) { Remove-Item -LiteralPath $transaction.current -Recurse -Force -ErrorAction SilentlyContinue }
    Remove-Item -LiteralPath $transaction.stage -Recurse -Force -ErrorAction SilentlyContinue
    if ($transaction.backupCreated -and (Test-Path -LiteralPath $transaction.backup)) {
      Move-Item -LiteralPath $transaction.backup -Destination $transaction.current -ErrorAction SilentlyContinue
    }
  }
}
function Commit-PackagedLocalCacheMirrors([System.Collections.Generic.List[object]]$Transactions) {
  foreach ($transaction in $Transactions) {
    Remove-Item -LiteralPath $transaction.stage,$transaction.backup -Recurse -Force -ErrorAction SilentlyContinue
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
if (-not (Test-Path -LiteralPath (Join-Path $payloadPath 'bin\legion.exe') -PathType Leaf)) { throw 'Staged Legion executable missing' }
$hadCurrent = $null -ne (Get-Item -LiteralPath $currentPath -Force -ErrorAction SilentlyContinue)
$hadVersion = $null -ne (Get-Item -LiteralPath $versionPath -Force -ErrorAction SilentlyContinue)
$currentBackupCreated = $false
$versionBackupCreated = $false
$currentReplaced = $false
$versionReplaced = $false
$mirrorTransactions = [System.Collections.Generic.List[object]]::new()
Write-InstallEvent 'activation' 'started' "version=$Version"
try {
  # Build and validate a clean current candidate before moving prior current.
  Copy-Item -LiteralPath $payloadPath -Destination $stagePath -Recurse
  $stagedLegion = Join-Path $stagePath 'bin\legion.exe'
  if ($env:LEGION_INSTALL_TEST_MODE -eq 'staged-validation-failure') { throw 'Forced staged payload validation failure' }
  $stagedVersion = ([string](Invoke-Bounded 'staged-version' $stagedLegion @('--version'))).Trim()
  if ($stagedVersion -ne $Version) { throw "Staged payload returned version $stagedVersion" }

  if ($hadCurrent) { Move-Item -LiteralPath $currentPath -Destination $backupPath; $currentBackupCreated = $true }
  if ($hadVersion) { Move-Item -LiteralPath $versionPath -Destination $versionBackupPath; $versionBackupCreated = $true }
  Move-Item -LiteralPath $payloadPath -Destination $versionPath
  $versionReplaced = $true
  Move-Item -LiteralPath $stagePath -Destination $currentPath
  $currentReplaced = $true
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
  Sync-PackagedLocalCacheMirrors $versionPath $mirrorTransactions
  $versionHash = Get-BinaryHash (Join-Path $versionPath 'bin\legion.exe')
  $currentHash = Get-BinaryHash $legion
  if ($currentHash -ne $versionHash) { throw "Activation hash mismatch: $currentHash != $versionHash" }
  [ordered]@{schema='legion.install.activation.v1';state='activated';current=$currentPath;target=$versionPath;previous=$null;refresh='complete'} | ConvertTo-Json -Compress | Set-Content -LiteralPath (Join-Path $rootPath 'activation.json') -Encoding UTF8
  Write-InstallEvent 'activation' 'complete' "version=$Version"
  Commit-PackagedLocalCacheMirrors $mirrorTransactions
  Remove-Item -LiteralPath $backupPath,$versionBackupPath -Recurse -Force -ErrorAction SilentlyContinue
  Remove-Item -LiteralPath $payloadPath -Recurse -Force -ErrorAction SilentlyContinue
} catch {
  Restore-PackagedLocalCacheMirrors $mirrorTransactions
  if ($currentReplaced) { Remove-Item -LiteralPath $currentPath -Recurse -Force -ErrorAction SilentlyContinue }
  if ($versionReplaced) { Remove-Item -LiteralPath $versionPath -Recurse -Force -ErrorAction SilentlyContinue }
  Remove-Item -LiteralPath $stagePath,$payloadPath -Recurse -Force -ErrorAction SilentlyContinue
  if ($currentBackupCreated -and (Test-Path -LiteralPath $backupPath)) { Move-Item -LiteralPath $backupPath -Destination $currentPath }
  if ($versionBackupCreated -and (Test-Path -LiteralPath $versionBackupPath)) { Move-Item -LiteralPath $versionBackupPath -Destination $versionPath }
  Write-InstallEvent 'activation' 'failed' ($_ | Out-String).Trim()
  Write-InstallEvent 'rollback' 'complete' $(if ($hadCurrent) { 'previous current restored' } else { 'new current removed' })
  throw
}
