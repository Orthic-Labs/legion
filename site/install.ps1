Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$releaseBootstrap = 'https://github.com/Orthic-Labs/legion/releases/latest/download/install.ps1'
try {
  $source = Invoke-RestMethod -Uri $releaseBootstrap -Headers @{ 'User-Agent' = 'Legion-Bootstrap' }
  if ([string]::IsNullOrWhiteSpace([string]$source)) { throw 'GitHub release bootstrap was empty' }
  & ([ScriptBlock]::Create([string]$source))
} catch {
  Write-Error "Legion installation failed: $($_.Exception.Message)"
  exit 1
}
