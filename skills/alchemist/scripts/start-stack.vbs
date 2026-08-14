' Alchemist stack launcher (Windows) — starts the OmniRoute gateway and the Alchemist
' viewer together, both windowless. Installed as a Startup-folder shortcut.
'
'   gateway : http://localhost:20128   (providers, keys, quota — infrastructure)
'   viewer  : http://127.0.0.1:8790    (briefs, worker commands, patches — the chats)
'
' Windowless by design: the workspace rule is "launch no visible Windows console for
' background automation". WshShell.Run with intWindowStyle 0 and bWaitOnReturn False.
'
' Idempotent: each service is probed first, so running this twice does not start a
' second copy and fight over the port.

Option Explicit

Dim shell, fso
Set shell = CreateObject("WScript.Shell")
Set fso   = CreateObject("Scripting.FileSystemObject")

Dim omniroute, pythonw, viewer
omniroute = "C:\nvm4w\nodejs\omniroute.cmd"
pythonw   = "C:\Users\adrds\AppData\Local\Programs\Python\Python311\pythonw.exe"
viewer    = "D:\workspace\tools\skills\alchemist\scripts\viewer.py"

' Returns True when something already answers on the given URL.
Function Listening(url)
    Dim http
    Listening = False
    On Error Resume Next
    Set http = CreateObject("MSXML2.ServerXMLHTTP.6.0")
    If Err.Number <> 0 Then Exit Function
    http.setTimeouts 2000, 2000, 2000, 3000
    http.Open "GET", url, False
    http.Send
    If Err.Number = 0 Then Listening = True
    Err.Clear
    On Error GoTo 0
End Function

' Gateway first — the viewer is useless without runs, and runs need the gateway.
If fso.FileExists(omniroute) Then
    If Not Listening("http://127.0.0.1:20128/healthz") Then
        ' No --tray: OmniRoute's own tray never fires when started hidden. tray.ps1
        ' below is ours and covers both services. --no-open stops a browser tab at login.
        shell.Run """" & omniroute & """ serve --no-open", 0, False
    End If
End If

If fso.FileExists(pythonw) And fso.FileExists(viewer) Then
    If Not Listening("http://127.0.0.1:8790/") Then
        ' cwd = script dir so `from parse_events import ...` resolves.
        shell.CurrentDirectory = fso.GetParentFolderName(viewer)
        shell.Run """" & pythonw & """ """ & viewer & """ --port 8790", 0, False
    End If
End If

' Tray last, so its first health poll finds both services already coming up.
' One tray only: a second copy would duplicate the icon.
Dim tray
tray = fso.GetParentFolderName(viewer) & "\tray.ps1"
If fso.FileExists(tray) Then
    Dim wmi, running, proc
    running = False
    On Error Resume Next
    Set wmi = GetObject("winmgmts:\\.\root\cimv2")
    For Each proc In wmi.ExecQuery("SELECT CommandLine FROM Win32_Process WHERE Name='powershell.exe'")
        If InStr(1, proc.CommandLine & "", "tray.ps1", 1) > 0 Then running = True
    Next
    On Error GoTo 0
    If Not running Then
        shell.Run "powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File """ & tray & """", 0, False
    End If
End If
