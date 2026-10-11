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
$legacyCodexSnapshotRoot = Join-Path $rootPath ('.rollback-codex-' + [Guid]::NewGuid().ToString('N'))
$stagePath = Join-Path $rootPath ('.next-current-' + [Guid]::NewGuid().ToString('N'))
$eventLog = if ($env:LEGION_INSTALL_EVENT_LOG) { [IO.Path]::GetFullPath($env:LEGION_INSTALL_EVENT_LOG) } else { Join-Path $rootPath 'install-events.jsonl' }
if ($env:LEGION_INSTALL_CHILD_TIMEOUT_SECONDS -match '^\d+$') {
  $ChildTimeoutSeconds = [Math]::Max(1, [Math]::Min(600, [int]$env:LEGION_INSTALL_CHILD_TIMEOUT_SECONDS))
}
foreach ($path in @($currentPath, $versionPath, $payloadPath, $backupPath, $versionBackupPath, $legacyCodexSnapshotRoot, $stagePath)) {
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
function Get-LegacyCodexProjection([string]$StateRoot, [string]$Home, [string]$InstallRoot) {
  $target = [IO.Path]::GetFullPath((Join-Path $Home '.codex\plugins\legion'))
  $ledgerPath = Join-Path $StateRoot 'integrations\projections\codex.json'
  if (-not (Test-Path -LiteralPath $ledgerPath -PathType Leaf) -or -not (Test-Path -LiteralPath $target -PathType Container)) { return $null }
  try {
    $stateItem = Get-Item -LiteralPath $StateRoot -Force
    if (($stateItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { return $null }
    $ledgerItem = Get-Item -LiteralPath $ledgerPath -Force
    if (($ledgerItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { return $null }
    $ledgerBytes = [IO.File]::ReadAllBytes($ledgerPath)
    $ledger = [Text.Encoding]::UTF8.GetString($ledgerBytes) | ConvertFrom-Json -ErrorAction Stop
    if ($ledger.schemaVersion -ne 1 -or $ledger.owner -cne 'legion-client-projection-v1' -or
        $ledger.clientId -cne 'codex' -or $ledger.projection -cne 'agent-plugins-with-explicit-sidecar' -or
        $ledger.origin -cne 'installed' -or $ledger.createdRoot -ne $true -or
        [IO.Path]::GetFullPath([string]$ledger.installRoot) -ine [IO.Path]::GetFullPath($InstallRoot) -or
        [IO.Path]::GetFullPath([string]$ledger.targetRoot) -ne $target) { return $null }
    $digests = [System.Collections.Generic.Dictionary[string,string]]::new([StringComparer]::Ordinal)
    foreach ($property in $ledger.files.PSObject.Properties) {
      $relative = ([string]$property.Name).Replace('\','/')
      if (-not $relative -or $relative.StartsWith('/') -or $relative -match '(^|/)\.\.?(/|$)') { return $null }
      $full = [IO.Path]::GetFullPath((Join-Path $target $relative))
      if (-not $full.StartsWith($target.TrimEnd('\') + '\', [StringComparison]::OrdinalIgnoreCase)) { return $null }
      $item = Get-Item -LiteralPath $full -Force -ErrorAction Stop
      if ($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { return $null }
      $digest = (Get-FileHash -LiteralPath $full -Algorithm SHA256).Hash.ToLowerInvariant()
      $expectedDigest = ([string]$property.Value).ToLowerInvariant()
      if (-not $expectedDigest.StartsWith('sha256:')) { return $null }
      $expectedDigest = $expectedDigest.Substring('sha256:'.Length)
      if ($digest -ne $expectedDigest) { return $null }
      $digests[$relative] = $digest
    }
    if ($digests.Count -eq 0) { return $null }
    foreach ($item in Get-ChildItem -LiteralPath $target -Recurse -Force) {
      if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { return $null }
      if (-not $item.PSIsContainer) {
        $relative = $item.FullName.Substring($target.TrimEnd('\').Length + 1).Replace('\','/')
        if (-not $digests.ContainsKey($relative)) { return $null }
      }
    }
    return [pscustomobject]@{ target=$target; ledger=$ledgerPath; ledgerBytes=$ledgerBytes; digests=$digests; stateRoot=$StateRoot; home=$Home; config=(Get-CodexDisabledIntent $Home) }
  } catch { return $null }
}
function Save-LegacyCodexProjection($Projection, [string]$BackupRoot) {
  if ($null -eq $Projection) { return $null }
  $savedRoot = Join-Path $BackupRoot 'codex-plugin'
  $savedLedger = Join-Path $BackupRoot 'codex-projection-ledger.json'
  New-Item -ItemType Directory -Path $BackupRoot -Force | Out-Null
  Copy-Item -LiteralPath $Projection.target -Destination $savedRoot -Recurse -Force
  [IO.File]::WriteAllBytes($savedLedger, $Projection.ledgerBytes)
  return [pscustomobject]@{ target=$Projection.target; ledger=$Projection.ledger; savedRoot=$savedRoot; savedLedger=$savedLedger; digests=$Projection.digests; stateRoot=$Projection.stateRoot; home=$Projection.home; config=$Projection.config }
}
function Get-CodexPluginConfig([string]$Text) {
  $lines = @($Text -split "`r?`n")
  $headers = @()
  for ($i = 0; $i -lt $lines.Count; $i++) {
    if ($lines[$i].Trim() -match '^\[\s*plugins\s*\.\s*(?:"legion@legion-installed"|legion@legion-installed)\s*\]$') { $headers += $i }
  }
  if ($headers.Count -gt 1) { return [pscustomobject]@{ valid=$false; state='invalid' } }
  if ($headers.Count -eq 0) { return [pscustomobject]@{ valid=$true; state='absent'; outside=($lines -join "`n"); block=@() } }
  $start = $headers[0]
  $end = $lines.Count
  for ($i = $start + 1; $i -lt $lines.Count; $i++) { if ($lines[$i].TrimStart().StartsWith('[')) { $end = $i; break } }
  $enabled = @()
  for ($i = $start + 1; $i -lt $end; $i++) {
    if ($lines[$i] -match '^\s*enabled\s*=') {
      if ($lines[$i] -match '^\s*enabled\s*=\s*(true|false)\s*(?:#.*)?$') { $enabled += $Matches[1].ToLowerInvariant() }
      else { return [pscustomobject]@{ valid=$false; state='invalid' } }
    }
  }
  if ($enabled.Count -gt 1) { return [pscustomobject]@{ valid=$false; state='invalid' } }
  $outsideLines = [System.Collections.Generic.List[string]]::new()
  for ($i = 0; $i -lt $lines.Count; $i++) { if ($i -lt $start -or $i -ge $end) { $outsideLines.Add($lines[$i]) } }
  return [pscustomobject]@{ valid=$true; state=$(if ($enabled.Count) { $enabled[0] } else { 'absent' }); outside=($outsideLines -join "`n"); block=@($lines[$start..($end - 1)]) }
}
function Get-CodexDisabledIntent([string]$Home) {
  $codexHome = if ($env:CODEX_HOME -and [IO.Path]::IsPathRooted($env:CODEX_HOME)) { [IO.Path]::GetFullPath($env:CODEX_HOME) } else { Join-Path $Home '.codex' }
  $config = Join-Path $codexHome 'config.toml'
  if (-not (Test-Path -LiteralPath $config -PathType Leaf)) { return $null }
  try {
    $parsed = Get-CodexPluginConfig ([IO.File]::ReadAllText($config))
    if (-not $parsed.valid -or $parsed.state -ne 'false') { return $null }
    return [pscustomobject]@{ path=$config; outside=$parsed.outside; block=$parsed.block }
  } catch { return $null }
}
function Restore-CodexDisabledIntent($Intent) {
  if ($null -eq $Intent) { return }
  if (-not (Test-Path -LiteralPath $Intent.path -PathType Leaf)) { throw 'Codex config disappeared; preserving current host state' }
  $currentText = [IO.File]::ReadAllText($Intent.path)
  $parsed = Get-CodexPluginConfig $currentText
  if (-not $parsed.valid) { throw 'Codex plugin config is ambiguous; preserving current host state' }
  if ($parsed.state -eq 'false') { return }
  if ($parsed.state -eq 'true') { throw 'Codex plugin enablement changed during activation; preserving current host choice' }
  if ($parsed.outside -cne $Intent.outside) { throw 'Unrelated Codex config changed during activation; preserving it' }
  $newline = if ($currentText.Contains("`r`n")) { "`r`n" } else { "`n" }
  $separator = if ($currentText.Length -gt 0 -and -not $currentText.EndsWith("`n")) { $newline } else { '' }
  $updated = $currentText + $separator + ($Intent.block -join $newline) + $newline
  $temporary = $Intent.path + '.legion-rollback-' + [Guid]::NewGuid().ToString('N')
  [IO.File]::WriteAllText($temporary, $updated, [Text.UTF8Encoding]::new($false))
  try { [IO.File]::Replace($temporary, $Intent.path, $null) }
  finally { if (Test-Path -LiteralPath $temporary) { Remove-Item -LiteralPath $temporary -Force -ErrorAction SilentlyContinue } }
}
function Restore-LegacyCodexProjection($Snapshot) {
  if ($null -eq $Snapshot) { return }
  $ledgerExists = Test-Path -LiteralPath $Snapshot.ledger -PathType Leaf
  if ($ledgerExists) {
    $existing = [IO.File]::ReadAllBytes($Snapshot.ledger)
    $saved = [IO.File]::ReadAllBytes($Snapshot.savedLedger)
    if ([Convert]::ToBase64String($existing) -cne [Convert]::ToBase64String($saved)) { throw 'Codex projection ledger changed during candidate activation; preserving it' }
  }
  if (Test-Path -LiteralPath $Snapshot.target) {
    $currentFiles = @(Get-ChildItem -LiteralPath $Snapshot.target -Recurse -File -Force)
    if ($currentFiles.Count -ne $Snapshot.digests.Count) { throw 'Codex plugin root changed during candidate activation; preserving it' }
    foreach ($item in Get-ChildItem -LiteralPath $Snapshot.target -Recurse -Force) {
      if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'Codex plugin root acquired a link during candidate activation; preserving it' }
    }
    foreach ($path in $Snapshot.digests.Keys) {
      $full = Join-Path $Snapshot.target $path
      if (-not (Test-Path -LiteralPath $full -PathType Leaf) -or (Get-FileHash -LiteralPath $full -Algorithm SHA256).Hash.ToLowerInvariant() -ne $Snapshot.digests[$path]) {
        throw "Codex plugin content changed during candidate activation: $path"
      }
    }
  } else {
    New-Item -ItemType Directory -Path (Split-Path -Parent $Snapshot.target) -Force | Out-Null
    Copy-Item -LiteralPath $Snapshot.savedRoot -Destination $Snapshot.target -Recurse
  }
  if (-not $ledgerExists) {
    New-Item -ItemType Directory -Path (Split-Path -Parent $Snapshot.ledger) -Force | Out-Null
    Copy-Item -LiteralPath $Snapshot.savedLedger -Destination $Snapshot.ledger
  }
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
$priorSupportsNativeMarketplace = $false
$priorRuntimeVersion = $null
$priorRuntimeHash = $null
$priorRuntimeBinary = Join-Path $currentPath 'bin\legion.exe'
if ($hadCurrent) {
  if (Test-Path -LiteralPath $priorRuntimeBinary -PathType Leaf) {
    try { $priorRuntimeHash = Get-BinaryHash $priorRuntimeBinary } catch { $priorRuntimeHash = $null }
    try { $priorRuntimeVersion = ([string](Invoke-Bounded 'prior-current-identity' $priorRuntimeBinary @('--version'))).Trim() } catch { $priorRuntimeVersion = $null }
  }
  $priorReleasePath = Join-Path $currentPath 'share\legion\release.json'
  try {
    if (Test-Path -LiteralPath $priorReleasePath -PathType Leaf) {
      $priorRelease = Get-Content -LiteralPath $priorReleasePath -Raw | ConvertFrom-Json -ErrorAction Stop
      $priorSupportsNativeMarketplace = $null -ne $priorRelease.nativeMarketplaces
    }
  } catch { $priorSupportsNativeMarketplace = $false }
}
$currentBackupCreated = $false
$versionBackupCreated = $false
$currentReplaced = $false
$versionReplaced = $false
$mirrorTransactions = [System.Collections.Generic.List[object]]::new()
$legacyCodexSnapshot = $null
$codexDisabledIntent = $null
Write-InstallEvent 'activation' 'started' "version=$Version"
try {
  $hostHome = if ($env:USERPROFILE) { [IO.Path]::GetFullPath($env:USERPROFILE) } else { [Environment]::GetFolderPath('UserProfile') }
  $stateRoot = if ($env:LEGION_STATE_ROOT) { [IO.Path]::GetFullPath($env:LEGION_STATE_ROOT) } else { Join-Path ([Environment]::GetFolderPath('LocalApplicationData')) 'Legion' }
  $codexDisabledIntent = Get-CodexDisabledIntent $hostHome
  $priorCodexProjection = Get-LegacyCodexProjection $stateRoot $hostHome $rootPath
  $legacyCodexSnapshot = Save-LegacyCodexProjection $priorCodexProjection $legacyCodexSnapshotRoot
  # Build and validate a clean current candidate before moving prior current.
  Copy-Item -LiteralPath $payloadPath -Destination $stagePath -Recurse
  $stagedLegion = Join-Path $stagePath 'bin\legion.exe'
  if ($env:LEGION_INSTALL_TEST_MODE -eq 'staged-validation-failure') { throw 'Forced staged payload validation failure' }
  $stagedVersion = ([string](Invoke-Bounded 'staged-version' $stagedLegion @('--version'))).Trim()
  if ($stagedVersion -ne $Version) { throw "Staged payload returned version $stagedVersion" }

  # Fresh staging no longer creates versions through Inno's file entries.
  New-Item -ItemType Directory -Path (Split-Path -Parent $versionPath) -Force | Out-Null
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
  Remove-Item -LiteralPath $backupPath,$versionBackupPath,$legacyCodexSnapshotRoot -Recurse -Force -ErrorAction SilentlyContinue
  Remove-Item -LiteralPath $payloadPath -Recurse -Force -ErrorAction SilentlyContinue
} catch {
  $activationError = ($_ | Out-String).Trim()
  $rollbackIssues = [System.Collections.Generic.List[string]]::new()
  Restore-PackagedLocalCacheMirrors $mirrorTransactions
  $candidateCleanupFailed = $false
  if (-not $priorSupportsNativeMarketplace -and $currentReplaced) {
    try {
      $candidateLegion = Join-Path $currentPath 'bin\legion.exe'
      $removeJson = Invoke-Bounded 'rollback-client-remove' $candidateLegion @('--json','setup','remove','--confirm')
      try { $remove = $removeJson | ConvertFrom-Json -ErrorAction Stop } catch { throw 'Client removal returned invalid JSON' }
      if ($remove.status -ne 'complete') { throw "Client removal status=$($remove.status)" }
    } catch {
      $candidateCleanupFailed = $true
      $rollbackIssues.Add("remove candidate native registrations: $(($_ | Out-String).Trim())") | Out-Null
    }
  }
  if ($candidateCleanupFailed) {
    $rollbackDetail = 'candidate current and payload retained because native registration cleanup could not be proven: ' + ($rollbackIssues -join '; ')
    Write-InstallEvent 'activation' 'failed' $activationError
    Write-InstallEvent 'rollback' 'failed' $rollbackDetail
    throw "Activation failed: $activationError; $rollbackDetail"
  }
  if ($currentReplaced) {
    try {
      Remove-Item -LiteralPath $currentPath -Recurse -Force -ErrorAction Stop
      if (Test-Path -LiteralPath $currentPath) { throw 'Candidate current still exists after removal' }
    } catch { $rollbackIssues.Add("remove candidate current: $(($_ | Out-String).Trim())") | Out-Null }
  }
  if ($versionReplaced) {
    try {
      Remove-Item -LiteralPath $versionPath -Recurse -Force -ErrorAction Stop
      if (Test-Path -LiteralPath $versionPath) { throw 'Candidate version still exists after removal' }
    } catch { $rollbackIssues.Add("remove candidate version: $(($_ | Out-String).Trim())") | Out-Null }
  }
  foreach ($temporaryPath in @($stagePath,$payloadPath)) {
    try { if (Test-Path -LiteralPath $temporaryPath) { Remove-Item -LiteralPath $temporaryPath -Recurse -Force -ErrorAction Stop } }
    catch { $rollbackIssues.Add("remove temporary payload: $(($_ | Out-String).Trim())") | Out-Null }
  }
  if ($rollbackIssues.Count -eq 0 -and $currentBackupCreated -and (Test-Path -LiteralPath $backupPath)) {
    try {
      if (Test-Path -LiteralPath $currentPath) { throw 'Candidate current still occupies restore destination' }
      Move-Item -LiteralPath $backupPath -Destination $currentPath -ErrorAction Stop
      $restoredBinary = Join-Path $currentPath 'bin\legion.exe'
      if (-not (Test-Path -LiteralPath $restoredBinary -PathType Leaf)) { throw 'Restored current executable missing' }
      if ($priorRuntimeVersion -and $priorRuntimeHash) {
        $restoredHash = Get-BinaryHash $restoredBinary
        if ($restoredHash -ne $priorRuntimeHash) { throw 'Restored current binary digest does not match prior runtime' }
        $restoredVersion = ([string](Invoke-Bounded 'rollback-identity' $restoredBinary @('--version'))).Trim()
        if ($restoredVersion -ne $priorRuntimeVersion) { throw "Restored current version=$restoredVersion expected=$priorRuntimeVersion" }
      } elseif ($hadCurrent) {
        throw 'Prior current identity could not be captured before activation'
      }
    } catch { $rollbackIssues.Add("restore prior current identity: $(($_ | Out-String).Trim())") | Out-Null }
  }
  if ($rollbackIssues.Count -eq 0 -and $versionBackupCreated -and (Test-Path -LiteralPath $versionBackupPath)) {
    try {
      if (Test-Path -LiteralPath $versionPath) { throw 'Candidate version still occupies restore destination' }
      Move-Item -LiteralPath $versionBackupPath -Destination $versionPath -ErrorAction Stop
      if (-not (Test-Path -LiteralPath (Join-Path $versionPath 'bin\legion.exe') -PathType Leaf)) { throw 'Restored version executable missing' }
    } catch { $rollbackIssues.Add("restore prior version: $(($_ | Out-String).Trim())") | Out-Null }
  }
  if ($rollbackIssues.Count -eq 0 -and $legacyCodexSnapshot) {
    try { Restore-LegacyCodexProjection $legacyCodexSnapshot }
    catch { $rollbackIssues.Add("restore prior owned Codex projection: $(($_ | Out-String).Trim())") | Out-Null }
  }
  if ($rollbackIssues.Count -eq 0 -and $currentReplaced) {
    try { Restore-CodexDisabledIntent $codexDisabledIntent }
    catch { $rollbackIssues.Add("restore prior Codex disabled choice: $(($_ | Out-String).Trim())") | Out-Null }
  }
  if ($rollbackIssues.Count -eq 0 -and $hadCurrent -and $currentReplaced -and (Test-Path -LiteralPath (Join-Path $currentPath 'bin\legion.exe') -PathType Leaf)) {
    try {
      $restoredLegion = Join-Path $currentPath 'bin\legion.exe'
      $repairJson = Invoke-Bounded 'rollback-client-refresh' $restoredLegion @('--json','setup','repair','--confirm')
      try { $repair = $repairJson | ConvertFrom-Json -ErrorAction Stop } catch { throw 'Restored client repair returned invalid JSON' }
      if ($repair.status -ne 'complete') { throw "Restored client repair status=$($repair.status)" }
    } catch {
      $rollbackIssues.Add("restore prior native registrations: $(($_ | Out-String).Trim())") | Out-Null
    }
  }
  if (-not $currentReplaced -and -not $versionReplaced) { Remove-Item -LiteralPath $legacyCodexSnapshotRoot -Recurse -Force -ErrorAction SilentlyContinue }
  Write-InstallEvent 'activation' 'failed' $activationError
  $rollbackDetail = if ($rollbackIssues.Count) { 'rollback issues: ' + ($rollbackIssues -join '; ') } elseif ($hadCurrent) { 'previous current and native registrations restored' } else { 'new current and native registrations removed' }
  Write-InstallEvent 'rollback' $(if ($rollbackIssues.Count) { 'failed' } else { 'complete' }) $rollbackDetail
  if ($rollbackIssues.Count) { throw "Activation failed: $activationError; $rollbackDetail" }
  throw
}
