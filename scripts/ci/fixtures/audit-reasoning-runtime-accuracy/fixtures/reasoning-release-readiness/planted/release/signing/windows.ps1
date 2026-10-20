$ErrorActionPreference = "Stop"
if (!(Test-Path $env:APP)) { throw "Missing unsigned executable" }
$certPath = Join-Path $env:RUNNER_TEMP "signing.pfx"
try {
  [IO.File]::WriteAllBytes($certPath, [Convert]::FromBase64String($env:WINDOWS_CERT_BASE64))
  $signtool = Get-ChildItem "${env:ProgramFiles(x86)}/Windows Kits/10/bin/*/x64/signtool.exe" | Sort-Object FullName -Descending | Select-Object -First 1
  if (!$signtool) { throw "Windows SDK signtool unavailable" }
  & $signtool.FullName sign /fd SHA256 /tr https://timestamp.digicert.com /td SHA256 /f $certPath /p $env:WINDOWS_CERT_PASSWORD $env:APP
  if ($LASTEXITCODE -ne 0) { throw "Signing failed" }
  & $signtool.FullName verify /pa $env:APP
  if ($LASTEXITCODE -ne 0) { throw "Signature verification failed" }
} finally { Remove-Item $certPath -ErrorAction SilentlyContinue }
