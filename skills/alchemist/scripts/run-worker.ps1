param(
    [Parameter(ValueFromPipeline = $true)][string]$InputObject,
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[A-Za-z0-9._-]+$')]
    [string]$Profile,
    [int]$TimeoutSeconds = 900,
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
$isolatedCodexHome = Join-Path ([IO.Path]::GetTempPath()) "alchemist-codex-$PID-$([guid]::NewGuid().ToString('N'))"
[IO.Directory]::CreateDirectory($isolatedCodexHome) | Out-Null
Copy-Item -LiteralPath $profilePath -Destination (Join-Path $isolatedCodexHome "$Profile.config.toml")
$modelCatalog = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..\model-catalog.json') -ErrorAction Stop).Path.Replace('\', '\\')
$minimalConfig = @"
model_catalog_json = "$modelCatalog"

[model_providers.omniroute]
name = "OmniRoute"
base_url = "http://127.0.0.1:20128/v1"
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
$omniroute = (Get-Command 'omniroute.cmd' -ErrorAction Stop).Source
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
$psi = [Diagnostics.ProcessStartInfo]::new()
$psi.FileName = $env:ComSpec
$psi.Arguments = "/d /s /c `"`"$omniroute`" launch-codex --profile $Profile -- exec --model $model --dangerously-bypass-approvals-and-sandbox --skip-git-repo-check --ephemeral --color never --cd `"$resolvedWorkDir`" -c approval_policy=`"never`" -c features.multi_agent=false --json - < `"%ALCHEMIST_INPUT_PATH%`" 1> `"%ALCHEMIST_EVENT_LOG%`" 2> `"%ALCHEMIST_STDERR_LOG%`"`""
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
if (-not $process.WaitForExit($TimeoutSeconds * 1000)) {
    try { & taskkill.exe /PID $process.Id /T /F 2>$null | Out-Null } catch { }; if (-not $process.HasExited) { try { $process.Kill() } catch { } }
    $process.WaitForExit()
    Remove-WithRetry $inputPath
    Remove-WithRetry $isolatedCodexHome -Recurse
    $workerSlot.ReleaseMutex(); $workerSlot.Dispose()
    [Console]::Error.WriteLine("EVENT_LOG=$EventLog")
    [Console]::Error.WriteLine("Alchemist worker timed out after ${TimeoutSeconds}s.")
    exit 124
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
