param(
    [Parameter(ValueFromPipeline = $true)][string]$InputObject,
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[A-Za-z0-9._-]+$')]
    [string]$Profile,
    [int]$TimeoutSeconds = 900,
    [int]$MaxInputBytes = 65536,
    [int]$MaxContextTokens = 131072,
    [int]$MaxOutputBytes = 10485760,
    [ValidateSet(0)][int]$RetryLimit = 0,
    [switch]$FullAccess,
    [string]$EventLog = '',
    [string]$WorkDir = (Get-Location).Path
)
$ErrorActionPreference = 'Stop'
function Remove-WithRetry([string]$Path, [switch]$Recurse) {
    for ($attempt = 0; $attempt -lt 20; $attempt++) {
        try { Remove-Item -LiteralPath $Path -Force -Recurse:$Recurse; return }
        catch { if ($attempt -eq 19) { throw }; Start-Sleep -Milliseconds 100 }
    }
}
function Remove-LeadingJsonPreamble([string]$Line) {
    if ($null -eq $Line) { return $Line }
    return $Line -replace '^[\s\uFEFF]+', ''
}
$brief = (@($input) -join [Environment]::NewLine).TrimStart([char]0xFEFF)
if ([string]::IsNullOrWhiteSpace($brief)) {
    throw 'Empty brief on stdin - refusing to spawn a worker with no task.'
}
$briefBytes = [Text.Encoding]::UTF8.GetByteCount($brief)
if ($briefBytes -gt $MaxInputBytes) {
    [Console]::Error.WriteLine("Worker input exceeded MaxInputBytes: ${briefBytes} > ${MaxInputBytes}.")
    exit 66
}
if ($TimeoutSeconds -lt 1 -or $MaxContextTokens -lt 1024 -or $MaxOutputBytes -lt 1) {
    throw 'TimeoutSeconds, MaxContextTokens, and MaxOutputBytes must be positive bounded values.'
}
$resolvedWorkDir = (Resolve-Path -LiteralPath $WorkDir -ErrorAction Stop).Path
if (-not (Test-Path -LiteralPath $resolvedWorkDir -PathType Container)) {
    throw "No such worker directory: $resolvedWorkDir"
}
$codexHome = if ($env:CODEX_HOME) { $env:CODEX_HOME } else { Join-Path $HOME '.codex' }
$profilePath = Join-Path $codexHome "$Profile.config.toml"
if (-not (Test-Path -LiteralPath $profilePath -PathType Leaf)) {
    throw "No such Codex profile: $profilePath"
}
$modelMatch = [regex]::Match((Get-Content -LiteralPath $profilePath -Raw), '(?m)^\s*model\s*=\s*"([A-Za-z0-9._:/-]+)"')
if (-not $modelMatch.Success) { throw "No safe model value in profile: $profilePath" }
$model = $modelMatch.Groups[1].Value
$omnirouteCommand = Get-Command 'omniroute' -ErrorAction SilentlyContinue
if (-not $omnirouteCommand) {
    [Console]::Error.WriteLine('OmniRoute worker adapter unavailable: `omniroute` is not on PATH. The adapter is optional; host-native Alchemist execution is unaffected.')
    exit 4
}
$omniroute = $omnirouteCommand.Source
$isolatedCodexHome = Join-Path ([IO.Path]::GetTempPath()) "alchemist-codex-$PID-$([guid]::NewGuid().ToString('N'))"
[IO.Directory]::CreateDirectory($isolatedCodexHome) | Out-Null
Copy-Item -LiteralPath $profilePath -Destination (Join-Path $isolatedCodexHome "$Profile.config.toml")
# The catalog entry is model-specific metadata: injecting it for any other
# selected model would stamp the wrong identity onto the profile's choice.
$modelCatalogPath = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..\model-catalog.json') -ErrorAction Stop).Path
$modelCataloged = @((Get-Content -LiteralPath $modelCatalogPath -Raw | ConvertFrom-Json).models | Where-Object { $_.slug -eq $model }).Count -gt 0
$modelCatalogLine = if ($modelCataloged) { "model_catalog_json = `"$($modelCatalogPath.Replace('\', '\\'))`"`r`n`r`n" } else { '' }
$gatewayUrl = if ($env:OMNIROUTE_URL) { $env:OMNIROUTE_URL.TrimEnd('/') } else { 'http://127.0.0.1:20128' }
$minimalConfig = @"
$modelCatalogLine[model_providers.omniroute]
name = "OmniRoute"
base_url = "$gatewayUrl/v1"
env_key = "OMNIROUTE_API_KEY"
wire_api = "responses"
requires_openai_auth = false
"@
[IO.File]::WriteAllText((Join-Path $isolatedCodexHome 'config.toml'), $minimalConfig, [Text.UTF8Encoding]::new($false))
$maxWorkers = if ($env:ALCHEMIST_MAX_CONCURRENT -match '^\d+$') {
    [Math]::Max(1, [Math]::Min(10, [int]$env:ALCHEMIST_MAX_CONCURRENT))
} else { 10 }
if (-not $EventLog) {
    $runDir = if ($env:ALCHEMIST_RUN_DIR) {
        $env:ALCHEMIST_RUN_DIR
    } else {
        Join-Path $HOME '.alchemist\runs'
    }
    [IO.Directory]::CreateDirectory($runDir) | Out-Null
    $EventLog = Join-Path $runDir "$(Get-Date -Format 'yyyyMMdd-HHmmss')-$Profile.jsonl"
} else {
    $parent = Split-Path -Parent $EventLog
    if ($parent) { [IO.Directory]::CreateDirectory($parent) | Out-Null }
}
$stderrPath = "$EventLog.stderr"
$utf8 = [Text.UTF8Encoding]::new($false)
$inputPath = "$EventLog.stdin"
[IO.File]::WriteAllText($inputPath, $brief, $utf8)
$workerSlot = $null
while ($null -eq $workerSlot) {
    for ($index = 0; $index -lt $maxWorkers; $index++) {
        $candidate = [Threading.Mutex]::new($false, "Local\AlchemistWorker-$index")
        try { $acquired = $candidate.WaitOne(0) } catch [Threading.AbandonedMutexException] { $acquired = $true }
        if ($acquired) { $workerSlot = $candidate; break }
        $candidate.Dispose()
    }
    if ($null -eq $workerSlot) { Start-Sleep -Milliseconds 500 }
}
# Bounded default: writes stay inside the workdir sandbox and approvals are
# never requested. Full host access is an explicit operator choice (-FullAccess),
# never the default.
$accessArgs = if ($FullAccess) { '--dangerously-bypass-approvals-and-sandbox' } else { '--sandbox workspace-write' }
$psi = [Diagnostics.ProcessStartInfo]::new()
$psi.FileName = $env:ComSpec
$psi.Arguments = "/d /s /c `"`"$omniroute`" launch-codex --profile $Profile -- exec --model $model $accessArgs --skip-git-repo-check --ephemeral --color never --cd `"$resolvedWorkDir`" -c approval_policy=`"never`" -c features.multi_agent=false -c model_context_window=$MaxContextTokens --json - < `"%ALCHEMIST_INPUT_PATH%`" 1> `"%ALCHEMIST_EVENT_LOG%`" 2> `"%ALCHEMIST_STDERR_LOG%`"`""
$psi.WorkingDirectory = $resolvedWorkDir
$psi.UseShellExecute = $false
$psi.CreateNoWindow = $true
$psi.RedirectStandardOutput = $false
$psi.RedirectStandardError = $false
$psi.EnvironmentVariables['CODEX_HOME'] = $isolatedCodexHome
$psi.EnvironmentVariables['ALCHEMIST_INPUT_PATH'] = $inputPath; $psi.EnvironmentVariables['ALCHEMIST_EVENT_LOG'] = $EventLog; $psi.EnvironmentVariables['ALCHEMIST_STDERR_LOG'] = $stderrPath
$process = [Diagnostics.Process]::new()
$process.StartInfo = $psi
try { $started = $process.Start() } catch {
    Remove-WithRetry $inputPath; Remove-WithRetry $isolatedCodexHome -Recurse
    $workerSlot.ReleaseMutex(); $workerSlot.Dispose(); throw
}
if (-not $started) {
    Remove-WithRetry $inputPath; Remove-WithRetry $isolatedCodexHome -Recurse
    $workerSlot.ReleaseMutex(); $workerSlot.Dispose()
    throw 'Failed to start OmniRoute Codex launcher.'
}
$deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
$limitReason = $null
while (-not $process.WaitForExit(100)) {
    $outputBytes = (Get-Item -LiteralPath $EventLog -ErrorAction SilentlyContinue).Length + (Get-Item -LiteralPath $stderrPath -ErrorAction SilentlyContinue).Length
    if ($outputBytes -gt $MaxOutputBytes) { $limitReason = "output exceeded MaxOutputBytes: ${outputBytes} > ${MaxOutputBytes}"; break }
    if ([DateTime]::UtcNow -ge $deadline) { $limitReason = "timed out after ${TimeoutSeconds}s"; break }
}
if ($limitReason) {
    try { & taskkill.exe /PID $process.Id /T /F 2>$null | Out-Null } catch { }; if (-not $process.HasExited) { try { $process.Kill() } catch { } }
    $process.WaitForExit()
    Remove-WithRetry $inputPath
    Remove-WithRetry $isolatedCodexHome -Recurse
    $workerSlot.ReleaseMutex(); $workerSlot.Dispose()
    [Console]::Error.WriteLine("EVENT_LOG=$EventLog")
    [Console]::Error.WriteLine("Alchemist worker limit exceeded: $limitReason. Useful output preserved.")
    if ($limitReason.StartsWith('timed out')) { exit 124 } else { exit 125 }
}
$jsonEventCount = 0
foreach ($line in [IO.File]::ReadLines($EventLog)) {
    $jsonLine = Remove-LeadingJsonPreamble $line
    if ([string]::IsNullOrWhiteSpace($jsonLine)) { continue }
    try { $null = $jsonLine | ConvertFrom-Json -ErrorAction Stop; $jsonEventCount++ } catch { }
}
Remove-WithRetry $inputPath
Remove-WithRetry $isolatedCodexHome -Recurse
$workerSlot.ReleaseMutex(); $workerSlot.Dispose()
if ($process.ExitCode -ne 0) {
    [Console]::Error.WriteLine("EVENT_LOG=$EventLog")
    [Console]::Error.WriteLine("Worker exited $($process.ExitCode); see $stderrPath")
    exit $process.ExitCode
}
if ($jsonEventCount -eq 0) {
    [Console]::Error.WriteLine("EVENT_LOG=$EventLog")
    [Console]::Error.WriteLine("Worker emitted zero JSON events; see $stderrPath")
    exit 65
}
$parser = Join-Path $PSScriptRoot 'parse_events.py'
$pythonCandidates = @(
    $env:ALCHEMIST_PYTHON,
    (Join-Path $env:LOCALAPPDATA 'Programs\Python\Python311\python.exe'),
    (Join-Path $HOME '.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe')
)
$python = $pythonCandidates | Where-Object { $_ -and (Test-Path -LiteralPath $_ -PathType Leaf) } | Select-Object -First 1
# Do not let Windows PowerShell add a BOM while forwarding normalized lines to
# the native parser. The parser must receive the same BOM-free JSON we counted.
$OutputEncoding = $utf8
if ($python) {
    Get-Content -LiteralPath $EventLog | ForEach-Object { Remove-LeadingJsonPreamble $_ } | & $python $parser --stream
} else {
    Get-Content -LiteralPath $EventLog | ForEach-Object { Remove-LeadingJsonPreamble $_ } | & py -3.11 $parser --stream
}
$parseStatus = $LASTEXITCODE
[Console]::Error.WriteLine("EVENT_LOG=$EventLog")
exit $parseStatus
