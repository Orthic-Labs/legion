# QA manual

Project owns `qa:browser` & `qa:browser:stop`: start hidden server on free `127.0.0.1`, enable deterministic mocks at IPC/API boundary, write URL/PID metadata, & stop only recorded process tree. Shared runners own browser interaction & viewport evidence. Test behavior before visual review; report findings, evidence, verification, skipped coverage, & cleanup.

Default to hidden browser QA. Use foreground/native work only for installer, file dialogs, OS hotkeys, devices, tray/window-frame, or packaged WebView behavior. Never capture desktop, wallpaper, another application, or browser chrome for routine QA.
