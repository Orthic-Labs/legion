param([Parameter(Mandatory=$true)][string]$InstallRoot, [Parameter(Mandatory=$true)][string]$Version)
$ErrorActionPreference = 'Stop'
$rootPath = [IO.Path]::GetFullPath($InstallRoot).TrimEnd('\')
if ($Version -notmatch '^\d+\.\d+\.\d+$') { throw 'Invalid Legion version' }
$currentPath = Join-Path $rootPath 'current'
$versionPath = Join-Path $rootPath ('versions\' + $Version)
$backupPath = Join-Path $rootPath ('.previous-current-' + [Guid]::NewGuid().ToString('N'))
foreach ($path in @($currentPath, $versionPath, $backupPath)) {
  if (-not [IO.Path]::GetFullPath($path).StartsWith($rootPath + '\', [StringComparison]::OrdinalIgnoreCase)) { throw 'Activation path escaped install root' }
}
if (-not (Test-Path -LiteralPath (Join-Path $versionPath 'bin\legion.exe') -PathType Leaf)) { throw 'Installed Legion executable missing' }
$hadCurrent = $null -ne (Get-Item -LiteralPath $currentPath -Force -ErrorAction SilentlyContinue)
if ($hadCurrent) { Move-Item -LiteralPath $currentPath -Destination $backupPath }
try {
  New-Item -ItemType Junction -Path $currentPath -Target $versionPath -ErrorAction Stop | Out-Null
} catch {
  if ($hadCurrent -and -not (Test-Path -LiteralPath $currentPath)) { Move-Item -LiteralPath $backupPath -Destination $currentPath }
  throw
}
[ordered]@{schema='legion.install.activation.v1';state='activated';current=$currentPath;target=$versionPath;previous=$(if($hadCurrent){$backupPath}else{$null})} | ConvertTo-Json -Compress | Set-Content -LiteralPath (Join-Path $rootPath 'activation.json') -Encoding UTF8
