# Alchemist stack tray icon (Windows).
#
# OmniRoute's own `serve --tray` does not fire when the server is started hidden
# (verified 2026-08-09: server healthy at 200 for 90s, tray never spawned — its
# init is gated behind a waitForServer callback that silently no-ops here). This
# is our own NotifyIcon so the tray is deterministic and carries both services.
#
# Menu: Dashboard (OmniRoute) · Citadel (run viewer) · Restart · Quit.

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

$GATEWAY = 'http://localhost:20128'
$CITADEL = 'http://127.0.0.1:8790'
$LAUNCHER = Join-Path $PSScriptRoot 'start-stack.vbs'

function Test-Up([string]$url) {
    try {
        $r = [System.Net.WebRequest]::Create($url)
        $r.Timeout = 2000
        $r.Method = 'GET'
        $r.GetResponse().Close()
        return $true
    } catch { return $false }
}

function Stop-Stack {
    Get-CimInstance Win32_Process -Filter "Name='node.exe' OR Name='cmd.exe'" -ErrorAction SilentlyContinue |
        Where-Object { $_.CommandLine -like '*omniroute*' } |
        ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }
    Get-CimInstance Win32_Process -Filter "Name='pythonw.exe' OR Name='python.exe'" -ErrorAction SilentlyContinue |
        Where-Object { $_.CommandLine -like '*viewer.py*' } |
        ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }
}

$tray = New-Object System.Windows.Forms.NotifyIcon
$tray.Icon = [System.Drawing.SystemIcons]::Application
$tray.Text = 'Alchemist stack'
$tray.Visible = $true

$menu = New-Object System.Windows.Forms.ContextMenuStrip

$mStatus = $menu.Items.Add('Checking...')
$mStatus.Enabled = $false
$menu.Items.Add('-') | Out-Null

$mDash = $menu.Items.Add('Open OmniRoute dashboard')
$mDash.add_Click({ Start-Process $GATEWAY })

$mCit = $menu.Items.Add('Open Citadel (runs)')
$mCit.add_Click({ Start-Process $CITADEL })

$menu.Items.Add('-') | Out-Null

$mRestart = $menu.Items.Add('Restart stack')
$mRestart.add_Click({
    Stop-Stack
    Start-Sleep -Seconds 3
    Start-Process 'wscript.exe' -ArgumentList "`"$LAUNCHER`"" -WindowStyle Hidden
})

$mQuit = $menu.Items.Add('Quit stack')
$mQuit.add_Click({
    Stop-Stack
    $tray.Visible = $false
    [System.Windows.Forms.Application]::Exit()
})

$tray.ContextMenuStrip = $menu
$tray.add_MouseDoubleClick({ Start-Process $CITADEL })

# Refresh the status line and tooltip so the icon is a real health indicator,
# not just a launcher.
$timer = New-Object System.Windows.Forms.Timer
$timer.Interval = 15000
$timer.add_Tick({
    $g = if (Test-Up "$GATEWAY/healthz") { 'up' } else { 'down' }
    $c = if (Test-Up $CITADEL) { 'up' } else { 'down' }
    $mStatus.Text = "OmniRoute: $g   Citadel: $c"
    $tray.Text = "Alchemist - OmniRoute $g, Citadel $c"
})
$timer.Start()

$g = if (Test-Up "$GATEWAY/healthz") { 'up' } else { 'down' }
$c = if (Test-Up $CITADEL) { 'up' } else { 'down' }
$mStatus.Text = "OmniRoute: $g   Citadel: $c"

[System.Windows.Forms.Application]::Run()
$tray.Dispose()
