param(
  [Parameter(Mandatory=$true)][string]$InstallRoot,
  [Parameter(Mandatory=$true)][string]$Version,
  [ValidateRange(1, 600)][int]$ChildTimeoutSeconds = 600
)
$ErrorActionPreference = 'Stop'
$rootPath = [IO.Path]::GetFullPath($InstallRoot).TrimEnd('\')
if ($Version -notmatch '^\d+\.\d+\.\d+$') { throw 'Invalid Legion version' }
$currentPath = Join-Path $rootPath 'current'
$payloadPath = Join-Path $rootPath ('.next-version-' + $Version)
$backupPath = Join-Path $rootPath 'current.previous'
$savedPreviousPath = Join-Path $rootPath '.next-previous'
$legacyCodexSnapshotRoot = Join-Path $rootPath '.rollback-codex'
$eventLog = if ($env:LEGION_INSTALL_EVENT_LOG) { [IO.Path]::GetFullPath($env:LEGION_INSTALL_EVENT_LOG) } else { Join-Path $rootPath 'install-events.jsonl' }
if ($env:LEGION_INSTALL_CHILD_TIMEOUT_SECONDS -match '^\d+$') {
  $ChildTimeoutSeconds = [Math]::Max(1, [Math]::Min(600, [int]$env:LEGION_INSTALL_CHILD_TIMEOUT_SECONDS))
}
foreach ($path in @($currentPath, $payloadPath, $backupPath, $savedPreviousPath, $legacyCodexSnapshotRoot)) {
  if (-not [IO.Path]::GetFullPath($path).StartsWith($rootPath + '\', [StringComparison]::OrdinalIgnoreCase)) { throw 'Activation path escaped install root' }
}
if (-not [IO.Path]::IsPathRooted($eventLog)) { throw 'Activation event log must be absolute' }
$eventDirectory = Split-Path -Parent $eventLog
if ($eventDirectory) { New-Item -ItemType Directory -Path $eventDirectory -Force | Out-Null }
function Write-InstallEvent([string]$Stage, [string]$Status, [string]$Detail = '') {
  [ordered]@{schema='legion.install.event.v1';timestamp=[DateTime]::UtcNow.ToString('o');stage=$Stage;status=$Status;detail=$Detail} |
    ConvertTo-Json -Compress | Add-Content -LiteralPath $eventLog -Encoding UTF8
}
trap {
  try { Write-InstallEvent 'activation' 'unhandled' ([string]$_.Exception.Message) } catch { }
  throw
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
function Remove-InstallTree([string]$Path) {
  $item = Get-Item -LiteralPath $Path -Force -ErrorAction SilentlyContinue
  if ($null -eq $item) { return }
  if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
    # Delete only the junction, never its target (legacy current points into versions).
    [IO.Directory]::Delete($Path)
  } else { Remove-Item -LiteralPath $Path -Recurse -Force -ErrorAction Stop }
}
function Get-PayloadDigests([string]$Path, [bool]$AllowRootLink = $false) {
  if (-not $AllowRootLink -and ((Get-Item -LiteralPath $Path -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw "Payload root is a reparse point: $Path" }
  $digests = [System.Collections.Generic.Dictionary[string,string]]::new([StringComparer]::OrdinalIgnoreCase)
  foreach ($item in Get-ChildItem -LiteralPath $Path -Recurse -Force) {
    if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw "Payload contains a reparse point: $($item.FullName)" }
    if (-not $item.PSIsContainer) { $digests[$item.FullName.Substring($Path.TrimEnd('\').Length + 1)] = Get-BinaryHash $item.FullName }
  }
  return ,$digests
}
function Save-CurrentPayload([string]$Current, [string]$Backup) {
  $owned = Get-OwnedPayload $Current (Split-Path -Parent $Current) $true
  $item = Get-Item -LiteralPath $Current -Force
  if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
    try {
      Copy-Item -LiteralPath $owned.root -Destination $Backup -Recurse
      # Check copied bytes without executing from the backup path.
      Assert-PayloadDigests $Backup $owned.digests
      Remove-InstallTree $Current
    } catch { Remove-InstallTree $Backup; throw }
  } else { Move-Item -LiteralPath $Current -Destination $Backup }
}
function Assert-PayloadDigests([string]$Path, $Digests) {
  $actual = Get-PayloadDigests $Path
  if ($actual.Count -ne $Digests.Count) { throw 'Activated payload file count changed' }
  foreach ($relative in $Digests.Keys) {
    if (-not $actual.ContainsKey($relative) -or $actual[$relative] -ne $Digests[$relative]) { throw "Activated payload hash mismatch: $relative" }
  }
}
function Assert-RealAncestors([string]$Path) {
  $cursor = [IO.Path]::GetFullPath($Path)
  while ($cursor) {
    $item = Get-Item -LiteralPath $cursor -Force -ErrorAction Stop
    if (-not $item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw "Install ancestor is not a real directory: $cursor" }
    $cursor = [IO.Path]::GetDirectoryName($cursor)
  }
}
function Get-OwnedPayload([string]$Path, [string]$ProductRoot, [bool]$AllowLegacyJunction = $false) {
  Assert-RealAncestors (Split-Path -Parent $Path)
  $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
  $payloadRoot = $Path
  $legacyTarget = $null
  if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
    $targets = @($item.Target)
    if (-not $AllowLegacyJunction -or $item.LinkType -ne 'Junction' -or $targets.Count -ne 1) { throw "Unsupported prior payload link: $Path" }
    $payloadRoot = [IO.Path]::GetFullPath([string]$targets[0]).TrimEnd('\')
    $versionsRoot = Join-Path $ProductRoot 'versions'
    if ((Split-Path -Parent $payloadRoot) -ine $versionsRoot -or (Split-Path -Leaf $payloadRoot) -notmatch '^\d+\.\d+\.\d+$') { throw "Prior current junction is outside owned version layout: $Path" }
    Assert-RealAncestors $payloadRoot
    $legacyTarget = $payloadRoot
  }
  $digests = Get-PayloadDigests $payloadRoot
  $release = Get-Content -LiteralPath (Join-Path $payloadRoot 'share\legion\release.json') -Raw | ConvertFrom-Json -ErrorAction Stop
  $releaseVersion = [string]$release.releaseVersion
  $plugin = Get-Content -LiteralPath (Join-Path $payloadRoot 'plugin\.claude-plugin\plugin.json') -Raw | ConvertFrom-Json -ErrorAction Stop
  if ($releaseVersion -notmatch '^\d+\.\d+\.\d+$' -or $release.runtime.platform -ne 'windows' -or
      $plugin.name -cne 'legion' -or $plugin.version -cne $releaseVersion -or
      ($legacyTarget -and (Split-Path -Leaf $legacyTarget) -cne $releaseVersion)) { throw "Prior payload lacks owned Windows release identity: $Path" }
  $declaredHash = ([string]$release.runtime.sha256).ToLowerInvariant() -replace '^sha256:', ''
  if ($declaredHash -notmatch '^[a-f0-9]{64}$' -or $declaredHash -ne (Get-BinaryHash (Join-Path $payloadRoot 'bin\legion.exe')).ToLowerInvariant()) { throw "Prior payload runtime digest is invalid: $Path" }
  return [pscustomobject]@{ root=$payloadRoot; legacyTarget=$legacyTarget; release=$release; digests=$digests; version=$releaseVersion; runtimeHash=$declaredHash }
}
function Assert-NoRecoveryRoot([string]$Path) {
  if ($null -ne (Get-Item -LiteralPath $Path -Force -ErrorAction SilentlyContinue)) { throw "Preserving unfinished or unowned recovery root: $Path" }
}
function Get-CanonicalByteArrayDigest([byte[]]$Bytes) {
  $canonicalBytes = ConvertTo-Json -InputObject ([int[]]$Bytes) -Compress
  $hasher = [Security.Cryptography.SHA256]::Create()
  try { return [BitConverter]::ToString($hasher.ComputeHash([Text.Encoding]::UTF8.GetBytes($canonicalBytes))).Replace('-', '').ToLowerInvariant() }
  finally { $hasher.Dispose() }
}
function Get-LegacyCodexProjection([string]$StateRoot, [string]$ClientHome, [string]$InstallRoot) {
  $target = [IO.Path]::GetFullPath((Join-Path $ClientHome '.codex\plugins\legion'))
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
      $digest = Get-CanonicalByteArrayDigest ([IO.File]::ReadAllBytes($full))
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
    return [pscustomobject]@{ target=$target; ledger=$ledgerPath; ledgerBytes=$ledgerBytes; digests=$digests; stateRoot=$StateRoot; home=$ClientHome; config=(Get-CodexDisabledIntent $ClientHome) }
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
function Get-CodexDisabledIntent([string]$ClientHome) {
  $codexHome = if ($env:CODEX_HOME -and [IO.Path]::IsPathRooted($env:CODEX_HOME)) { [IO.Path]::GetFullPath($env:CODEX_HOME) } else { Join-Path $ClientHome '.codex' }
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
      if (-not (Test-Path -LiteralPath $full -PathType Leaf) -or (Get-CanonicalByteArrayDigest ([IO.File]::ReadAllBytes($full))) -ne $Snapshot.digests[$path]) {
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
function Sync-PackagedLocalCacheMirrors([string]$CurrentPath, [System.Collections.Generic.List[object]]$Transactions) {
  $localAppData = [Environment]::GetFolderPath('LocalApplicationData')
  $packagesRoot = if ($env:LEGION_INSTALL_PACKAGES_ROOT) { [IO.Path]::GetFullPath($env:LEGION_INSTALL_PACKAGES_ROOT) } else { Join-Path $localAppData 'Packages' }
  if (-not (Test-Path -LiteralPath $packagesRoot -PathType Container)) { return }
  foreach ($package in Get-ChildItem -LiteralPath $packagesRoot -Directory -ErrorAction SilentlyContinue) {
    $mirrorProductRoot = Join-Path $package.FullName 'LocalCache\Local\Orthic Labs\Legion'
    if (-not (Test-Path -LiteralPath $mirrorProductRoot -PathType Container)) { continue }
    $mirrorCurrent = Join-Path $mirrorProductRoot 'current'
    $stagePath = Join-Path $mirrorProductRoot ('.next-current-' + [Guid]::NewGuid().ToString('N'))
    $backupPath = Join-Path $mirrorProductRoot 'current.previous'
    $savedPrevious = Join-Path $mirrorProductRoot '.next-previous'
    $transaction = [pscustomobject]@{current=$mirrorCurrent;stage=$stagePath;backup=$backupPath;savedPrevious=$savedPrevious;previousSaved=$false;backupCreated=$false;replacementCreated=$false}
    $Transactions.Add($transaction) | Out-Null
    try {
      Write-InstallEvent 'localcache-mirror' 'started' $mirrorCurrent
      Assert-RealAncestors $mirrorProductRoot
      Assert-NoRecoveryRoot $savedPrevious
      $priorMirror = if (Test-Path -LiteralPath $mirrorCurrent) { Get-OwnedPayload $mirrorCurrent $mirrorProductRoot $true } else { $null }
      if (Test-Path -LiteralPath $backupPath) { $null = Get-OwnedPayload $backupPath $mirrorProductRoot }
      Copy-Item -LiteralPath $CurrentPath -Destination $stagePath -Recurse
      Assert-PayloadDigests $stagePath (Get-PayloadDigests $CurrentPath)
      if (Test-Path -LiteralPath $backupPath) {
        Move-Item -LiteralPath $backupPath -Destination $savedPrevious
        $transaction.previousSaved = $true
      }
      if (Test-Path -LiteralPath $mirrorCurrent) {
        Save-CurrentPayload $mirrorCurrent $backupPath
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
    if ($transaction.replacementCreated) { Remove-InstallTree $transaction.current }
    Remove-InstallTree $transaction.stage
    if ($transaction.backupCreated) {
      if (-not (Test-Path -LiteralPath $transaction.backup)) { throw 'Packaged LocalCache prior payload disappeared during rollback' }
      Move-Item -LiteralPath $transaction.backup -Destination $transaction.current -ErrorAction Stop
    }
    if ($transaction.previousSaved) {
      Move-Item -LiteralPath $transaction.savedPrevious -Destination $transaction.backup -ErrorAction Stop
    }
  }
}
function Commit-PackagedLocalCacheMirrors([System.Collections.Generic.List[object]]$Transactions) {
  foreach ($transaction in $Transactions) {
    Remove-InstallTree $transaction.stage
    Remove-InstallTree $transaction.savedPrevious
  }
}
function Invoke-Bounded([string]$Stage, [string]$FilePath, [string[]]$Arguments) {
  if ([IO.Path]::GetFileName($FilePath) -ieq 'legion.exe' -and [IO.Path]::GetFullPath($FilePath) -ine (Join-Path $currentPath 'bin\legion.exe')) { throw "$Stage attempted to execute Legion outside stable current" }
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
    Write-InstallEvent $Stage 'started' "executable=$FilePath; timeout=${ChildTimeoutSeconds}s"
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
$lockHasher = [Security.Cryptography.SHA256]::Create()
try { $lockKey = [BitConverter]::ToString($lockHasher.ComputeHash([Text.Encoding]::UTF8.GetBytes($rootPath.ToLowerInvariant()))).Replace('-', '') }
finally { $lockHasher.Dispose() }
$activationMutex = [Threading.Mutex]::new($false, ('Local\OrthicLabs.Legion.Activation.' + $lockKey))
$lockAcquired = $false
try {
  try { $lockAcquired = $activationMutex.WaitOne(30000) }
  catch [Threading.AbandonedMutexException] { $lockAcquired = $true }
  if (-not $lockAcquired) { throw 'Another Legion activation holds this install root (30s timeout)' }
  Write-InstallEvent 'activation-lock' 'complete' 'exclusive install-root lock acquired'
if (-not (Test-Path -LiteralPath (Join-Path $payloadPath 'bin\legion.exe') -PathType Leaf)) { throw 'Staged Legion executable missing' }
$hadCurrent = $null -ne (Get-Item -LiteralPath $currentPath -Force -ErrorAction SilentlyContinue)
$priorSupportsNativeMarketplace = $false
$priorRuntimeVersion = $null
$priorRuntimeHash = $null
$priorPayload = $null
$currentBackupCreated = $false
$previousSaved = $false
$currentReplaced = $false
$mirrorTransactions = [System.Collections.Generic.List[object]]::new()
$legacyCodexSnapshot = $null
$codexDisabledIntent = $null
$clientRegistrationAttempted = $false
$candidateValidated = $false
$receiptMutationAttempted = $false
$payloadOwned = $false
$activationReceiptPath = Join-Path $rootPath 'activation.json'
$priorActivationReceipt = if (Test-Path -LiteralPath $activationReceiptPath -PathType Leaf) { [IO.File]::ReadAllBytes($activationReceiptPath) } else { $null }
Write-InstallEvent 'activation' 'started' "version=$Version"
try {
  Assert-RealAncestors $rootPath
  # Treat staging as data only; ownership & runtime digest precede cleanup or execution.
  $stagedPayload = Get-OwnedPayload $payloadPath $rootPath
  if ($stagedPayload.version -cne $Version) { throw 'Staged payload declares an unexpected Windows release identity' }
  $payloadDigests = $stagedPayload.digests
  $payloadOwned = $true
  if ($env:LEGION_INSTALL_TEST_MODE -eq 'staged-validation-failure') { throw 'Forced staged payload validation failure' }
  Assert-NoRecoveryRoot $savedPreviousPath
  Assert-NoRecoveryRoot $legacyCodexSnapshotRoot
  if ($hadCurrent) {
    $priorPayload = Get-OwnedPayload $currentPath $rootPath $true
    $priorRuntimeVersion = $priorPayload.version
    $priorRuntimeHash = $priorPayload.runtimeHash
    $priorSupportsNativeMarketplace = $null -ne $priorPayload.release.nativeMarketplaces
  }
  if (Test-Path -LiteralPath $backupPath) { $null = Get-OwnedPayload $backupPath $rootPath }
  $hostHome = if ($env:USERPROFILE) { [IO.Path]::GetFullPath($env:USERPROFILE) } else { [Environment]::GetFolderPath('UserProfile') }
  $stateRoot = if ($env:LEGION_STATE_ROOT) { [IO.Path]::GetFullPath($env:LEGION_STATE_ROOT) } else { Join-Path ([Environment]::GetFolderPath('LocalApplicationData')) 'Legion' }
  $codexDisabledIntent = Get-CodexDisabledIntent $hostHome
  $priorCodexProjection = Get-LegacyCodexProjection $stateRoot $hostHome $rootPath
  $legacyCodexSnapshot = Save-LegacyCodexProjection $priorCodexProjection $legacyCodexSnapshotRoot
  if (Test-Path -LiteralPath $backupPath) {
    Move-Item -LiteralPath $backupPath -Destination $savedPreviousPath
    $previousSaved = $true
  }
  if ($hadCurrent) {
    # Materialize legacy junctions so rollback restores a real current folder.
    Save-CurrentPayload $currentPath $backupPath
    $currentBackupCreated = $true
  }
  Move-Item -LiteralPath $payloadPath -Destination $currentPath
  $currentReplaced = $true
  Assert-PayloadDigests $currentPath $payloadDigests
  $legion = Join-Path $currentPath 'bin\legion.exe'
  $reportedVersion = ([string](Invoke-Bounded 'activation-version' $legion @('--version'))).Trim()
  if ($reportedVersion -ne $Version) { throw "Activation verification returned version $reportedVersion" }
  $candidateValidated = $true
  if ($env:LEGION_INSTALL_TEST_MODE -eq 'refresh-failure') { throw 'Forced client refresh failure' }
  if ($env:LEGION_INSTALL_TEST_MODE -eq 'stalled-child') {
    Invoke-Bounded 'client-refresh' "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" @('-NoProfile','-NonInteractive','-Command','Start-Sleep -Seconds 30') | Out-Null
  } else {
    $clientRegistrationAttempted = $true
    $refreshJson = Invoke-Bounded 'client-refresh' $legion @('--json','setup','repair','--confirm')
    try { $refresh = $refreshJson | ConvertFrom-Json -ErrorAction Stop } catch { throw 'Client refresh returned invalid JSON' }
    if ($refresh.status -ne 'complete') { throw "Client refresh status=$($refresh.status)" }
  }
  Sync-PackagedLocalCacheMirrors $currentPath $mirrorTransactions
  Assert-PayloadDigests $currentPath $payloadDigests
  # Retire only the validated target consumed by this migration, never its siblings.
  if ($priorPayload -and $priorPayload.legacyTarget) {
    Assert-PayloadDigests $priorPayload.legacyTarget $priorPayload.digests
    Remove-InstallTree $priorPayload.legacyTarget
    $versionsRoot = Split-Path -Parent $priorPayload.legacyTarget
    if (@(Get-ChildItem -LiteralPath $versionsRoot -Force).Count -eq 0) { [IO.Directory]::Delete($versionsRoot) }
  }
  # Set the rollback obligation before any write can truncate prior evidence.
  $receiptMutationAttempted = $true
  [ordered]@{schema='legion.install.activation.v1';state='activated';current=$currentPath;target=$currentPath;previous=$(if ($hadCurrent) { $backupPath } else { $null });refresh='complete'} | ConvertTo-Json -Compress | Set-Content -LiteralPath $activationReceiptPath -Encoding UTF8
  Write-InstallEvent 'activation' 'complete' "version=$Version"
  # Activation is committed; cleanup failures must not attempt a partial rollback.
  foreach ($cleanup in @($savedPreviousPath,$legacyCodexSnapshotRoot)) {
    try { Remove-InstallTree $cleanup } catch { Write-InstallEvent 'cleanup' 'failed' ([string]$_.Exception.Message) }
  }
  try { Commit-PackagedLocalCacheMirrors $mirrorTransactions }
  catch { Write-InstallEvent 'cleanup' 'failed' ([string]$_.Exception.Message) }
} catch {
  $activationError = ($_ | Out-String).Trim()
  $rollbackIssues = [System.Collections.Generic.List[string]]::new()
  try { Restore-PackagedLocalCacheMirrors $mirrorTransactions }
  catch { $rollbackIssues.Add("restore packaged mirrors: $(($_ | Out-String).Trim())") | Out-Null }
  $candidateCleanupFailed = $false
  if (-not $priorSupportsNativeMarketplace -and $clientRegistrationAttempted -and $candidateValidated -and $currentReplaced) {
    try {
      $candidateLegion = Join-Path $currentPath 'bin\legion.exe'
      Assert-PayloadDigests $currentPath $payloadDigests
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
      Remove-InstallTree $currentPath
      if (Test-Path -LiteralPath $currentPath) { throw 'Candidate current still exists after removal' }
    } catch { $rollbackIssues.Add("remove candidate current: $(($_ | Out-String).Trim())") | Out-Null }
  }
  foreach ($temporaryPath in @($payloadPath)) {
    try { if ($payloadOwned) { Remove-InstallTree $temporaryPath } }
    catch { $rollbackIssues.Add("remove temporary payload: $(($_ | Out-String).Trim())") | Out-Null }
  }
  $currentRestored = (-not $currentReplaced -and -not $currentBackupCreated) -or (-not $hadCurrent -and -not (Test-Path -LiteralPath $currentPath))
  if ($currentBackupCreated -and -not (Test-Path -LiteralPath $currentPath) -and (Test-Path -LiteralPath $backupPath)) {
    try {
      if (Test-Path -LiteralPath $currentPath) { throw 'Candidate current still occupies restore destination' }
      Move-Item -LiteralPath $backupPath -Destination $currentPath -ErrorAction Stop
      Assert-PayloadDigests $currentPath $priorPayload.digests
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
      $currentRestored = $true
    } catch { $rollbackIssues.Add("restore prior current identity: $(($_ | Out-String).Trim())") | Out-Null }
  }
  if ($currentBackupCreated -and -not $currentRestored -and $rollbackIssues.Count -eq 0) {
    $rollbackIssues.Add('Prior current payload could not be restored from current.previous') | Out-Null
  }
  if ($previousSaved -and -not (Test-Path -LiteralPath $backupPath)) {
    try {
      Move-Item -LiteralPath $savedPreviousPath -Destination $backupPath -ErrorAction Stop
    } catch { $rollbackIssues.Add("restore previous backup: $(($_ | Out-String).Trim())") | Out-Null }
  }
  if ($currentRestored -and $legacyCodexSnapshot) {
    try { Restore-LegacyCodexProjection $legacyCodexSnapshot }
    catch { $rollbackIssues.Add("restore prior owned Codex projection: $(($_ | Out-String).Trim())") | Out-Null }
  }
  if ($currentRestored -and $currentReplaced) {
    try { Restore-CodexDisabledIntent $codexDisabledIntent }
    catch { $rollbackIssues.Add("restore prior Codex disabled choice: $(($_ | Out-String).Trim())") | Out-Null }
  }
  if ($currentRestored -and $hadCurrent -and $currentReplaced -and (Test-Path -LiteralPath (Join-Path $currentPath 'bin\legion.exe') -PathType Leaf)) {
    try {
      $restoredLegion = Join-Path $currentPath 'bin\legion.exe'
      $repairJson = Invoke-Bounded 'rollback-client-refresh' $restoredLegion @('--json','setup','repair','--confirm')
      try { $repair = $repairJson | ConvertFrom-Json -ErrorAction Stop } catch { throw 'Restored client repair returned invalid JSON' }
      if ($repair.status -ne 'complete') { throw "Restored client repair status=$($repair.status)" }
    } catch {
      $rollbackIssues.Add("restore prior native registrations: $(($_ | Out-String).Trim())") | Out-Null
    }
  }
  if ($receiptMutationAttempted -and $currentRestored) {
    try {
      if ($null -ne $priorActivationReceipt) { [IO.File]::WriteAllBytes($activationReceiptPath, $priorActivationReceipt) }
      elseif (Test-Path -LiteralPath $activationReceiptPath) { Remove-Item -LiteralPath $activationReceiptPath -Force }
    } catch { $rollbackIssues.Add("restore prior activation receipt: $(($_ | Out-String).Trim())") | Out-Null }
  }
  if ($rollbackIssues.Count -eq 0) {
    if ($legacyCodexSnapshot) { Remove-InstallTree $legacyCodexSnapshotRoot }
  }
  Write-InstallEvent 'activation' 'failed' $activationError
  $rollbackDetail = if ($rollbackIssues.Count) { 'rollback issues: ' + ($rollbackIssues -join '; ') } elseif ($hadCurrent) { 'previous current and native registrations restored' } else { 'new current and native registrations removed' }
  Write-InstallEvent 'rollback' $(if ($rollbackIssues.Count) { 'failed' } else { 'complete' }) $rollbackDetail
  if ($rollbackIssues.Count) { throw "Activation failed: $activationError; $rollbackDetail" }
  throw
}
} finally {
  if ($lockAcquired) { $activationMutex.ReleaseMutex() }
  $activationMutex.Dispose()
}
