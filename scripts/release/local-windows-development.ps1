param(
    [switch]$BuildOnly,
    [switch]$DevelopmentProfile,
    [string]$PreassembledRoot,
    [string]$XtaskBinary
)

$ErrorActionPreference = 'Stop'
$repositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
$installerTask = $null

Push-Location $repositoryRoot
try {
    # DevelopmentProfile remains accepted for existing callers; this route
    # always uses Cargo's incremental dev profile.
    $env:RIGHTKIT_BUILD_MODE = 'dev'
    $env:RIGHTKIT_CARGO_PROFILE = 'dev'
    $env:CARGO_INCREMENTAL = '1'
    if ([bool]$PreassembledRoot -ne [bool]$XtaskBinary) {
        throw 'PreassembledRoot & XtaskBinary must be supplied together.'
    }
    if ($PreassembledRoot) {
        if ($env:GITHUB_ACTIONS -ne 'true' -or -not $BuildOnly) {
            throw 'Preassembled input is restricted to hosted CI BuildOnly packaging.'
        }
        $PreassembledRoot = (Resolve-Path -LiteralPath $PreassembledRoot).Path
        $installerTask = (Resolve-Path -LiteralPath $XtaskBinary).Path
    } elseif ($env:GITHUB_ACTIONS -eq 'true') {
        $compiler = 'cargo'
        $compilerPrefix = @()
    } else {
        $compiler = 'rustright'
        $compilerPrefix = @('cargo')
    }
    # Keep compilation inside RustRight. The local development policy permits
    # native builds, while arbitrary cargo-run commands remain denied.
    if (-not $PreassembledRoot) {
        & $compiler @compilerPrefix build --locked --profile dev --manifest-path engine/Cargo.toml `
            --target x86_64-pc-windows-msvc -p xtask --message-format=json-render-diagnostics |
            ForEach-Object {
                if ($_ -match '^\{') {
                    $record = $_ | ConvertFrom-Json
                    if ($record.reason -eq 'compiler-artifact' -and
                        $record.target.name -eq 'xtask' -and
                        $record.target.kind -contains 'bin' -and $record.executable) {
                        $installerTask = $record.executable
                    } elseif ($record.reason -eq 'compiler-message' -and $record.message.rendered) {
                        [Console]::Error.Write($record.message.rendered)
                    }
                } else {
                    Write-Output $_
                }
            }
        if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
    }
    if (-not $installerTask -or -not (Test-Path -LiteralPath $installerTask -PathType Leaf)) {
        throw 'Managed build did not return an xtask executable.'
    }

    $taskArguments = @('release-local-windows-development')
    if ($BuildOnly) { $taskArguments += '--build-only' }
    if ($PreassembledRoot) { $taskArguments += @('--preassembled-root', $PreassembledRoot) }
    & $installerTask @taskArguments
    $buildExitCode = $LASTEXITCODE
    if ($buildExitCode -ne 0) { exit $buildExitCode }

    if ($BuildOnly -and $env:GITHUB_ACTIONS -eq 'true') {
        $installerRoot = Join-Path $repositoryRoot 'dist/local-windows/installer'
        $qualificationRoot = Join-Path $repositoryRoot 'dist/local-windows/qualification'
        if (Test-Path -LiteralPath $qualificationRoot) {
            Remove-Item -LiteralPath $qualificationRoot -Recurse -Force
        }
        New-Item -ItemType Directory -Path $qualificationRoot -Force | Out-Null

        $env:RIGHT_GIT_FINALIZED_WINDOWS_ROOT = $installerRoot
        $env:RIGHT_GIT_QUALIFICATION_EVIDENCE_ROOT = $qualificationRoot
        & $installerTask 'release-qualify-installed'
        $qualificationExitCode = $LASTEXITCODE
        if ($qualificationExitCode -ne 0) { exit $qualificationExitCode }

        $qualificationFile = Join-Path $qualificationRoot 'qualification.json'
        if (-not (Test-Path -LiteralPath $qualificationFile -PathType Leaf)) {
            throw 'Installed qualification succeeded without qualification.json.'
        }
        Copy-Item -LiteralPath $qualificationFile -Destination (Join-Path $installerRoot 'qualification.json') -Force
    }

    exit 0
} finally {
    Pop-Location
}
