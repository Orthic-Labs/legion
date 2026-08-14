#!/usr/bin/env python3
"""Local viewer for Alchemist runs — a localhost page showing orchestrator↔worker traffic.

    python viewer.py [--port 8790] [--runs-dir ~/.alchemist/runs]

Stdlib only, loopback only. Reads the same JSONL event logs the worker runner writes and
classifies them with parse_events.classify, so the page and the CLI summary always agree.

Why this exists rather than a hosted dashboard: OmniRoute's dashboard shows infrastructure
(model, tokens, latency) and has no idea what the brief said or what the worker did. This
shows the semantic layer, on the machine, with nothing leaving it.
"""

from __future__ import annotations

import argparse
import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

from parse_events import classify, iter_events

RUNS_DIR = Path(os.environ.get("ALCHEMIST_RUN_DIR", Path.home() / ".alchemist" / "runs"))

PAGE = """<!doctype html><html><head><meta charset="utf-8"><title>Citadel — agent runs</title>
<style>
:root{color-scheme:light dark;--bg:#fff;--fg:#111;--dim:#666;--line:#e3e3e6;--card:#fafafa}
@media (prefers-color-scheme:dark){:root{--bg:#111318;--fg:#e8e8ea;--dim:#8b8b93;--line:#2a2d35;--card:#181b21}}
*{box-sizing:border-box}
body{margin:0;font:14px/1.5 ui-sans-serif,system-ui,-apple-system,Segoe UI,sans-serif;background:var(--bg);color:var(--fg)}
header{padding:12px 16px;border-bottom:1px solid var(--line);display:flex;gap:12px;align-items:center;flex-wrap:wrap}
h1{font-size:15px;margin:0;font-weight:600}
select,button{font:inherit;padding:4px 8px;background:var(--card);color:var(--fg);border:1px solid var(--line);border-radius:6px}
main{padding:12px 16px;max-width:1100px}
.ev{border-left:3px solid var(--line);padding:5px 10px;margin:5px 0;background:var(--card);border-radius:0 6px 6px 0;overflow-x:auto}
.k{font-size:11px;text-transform:uppercase;letter-spacing:.06em;color:var(--dim);margin-right:8px}
pre{margin:2px 0;white-space:pre-wrap;word-break:break-word;font:12.5px/1.45 ui-monospace,Menlo,Consolas,monospace}
.assistant{border-left-color:#3b82f6}.command{border-left-color:#8b5cf6}.patch{border-left-color:#10b981}
.error{border-left-color:#ef4444}.reasoning{border-left-color:#9ca3af;opacity:.75}.usage{opacity:.6}
.empty{color:var(--dim);padding:24px 0}
.count{color:var(--dim);font-size:12px}
</style></head><body>
<header>
  <h1>Citadel</h1>
  <select id="run"></select>
  <label><input type="checkbox" id="live" checked> live</label>
  <span class="count" id="count"></span>
</header>
<main><div id="log" class="empty">Select a run.</div></main>
<script>
const runSel=document.getElementById('run'),log=document.getElementById('log'),
      live=document.getElementById('live'),count=document.getElementById('count');
let current=null,seen=0;
async function loadRuns(){
  const runs=await (await fetch('/api/runs')).json();
  const keep=runSel.value;
  runSel.innerHTML=runs.map(r=>`<option value="${r.name}">${r.name} (${r.events})</option>`).join('');
  if(runs.length===0){log.className='empty';log.textContent='No runs yet. Invoke /alchemist to create one.';return;}
  runSel.value=runs.some(r=>r.name===keep)?keep:runs[0].name;
  if(current!==runSel.value){current=runSel.value;seen=0;log.innerHTML='';}
}
function esc(s){return s.replace(/[&<>]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;'}[c]))}
async function loadEvents(){
  if(!runSel.value)return;
  if(current!==runSel.value){current=runSel.value;seen=0;log.innerHTML='';}
  const evs=await (await fetch('/api/events?run='+encodeURIComponent(current)+'&from='+seen)).json();
  if(evs.length){
    log.className='';
    for(const e of evs){
      const d=document.createElement('div');d.className='ev '+e.kind;
      d.innerHTML='<span class="k">'+esc(e.kind)+'</span><pre>'+esc(e.detail||'')+'</pre>';
      log.appendChild(d);
    }
    seen+=evs.length;count.textContent=seen+' events';
    window.scrollTo(0,document.body.scrollHeight);
  }
}
runSel.onchange=()=>{seen=0;log.innerHTML='';loadEvents()};
loadRuns().then(loadEvents);
setInterval(()=>{if(live.checked){loadRuns();loadEvents();}},2000);
</script></body></html>"""


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass  # quiet; this is a local viewer, not a service

    def _send(self, status, body: bytes, ctype: str):
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _json(self, payload):
        self._send(200, json.dumps(payload).encode(), "application/json")

    def do_GET(self):
        parts = urlsplit(self.path)
        query = parse_qs(parts.query)

        if parts.path == "/":
            return self._send(200, PAGE.encode(), "text/html; charset=utf-8")

        if parts.path == "/api/runs":
            runs = []
            if RUNS_DIR.is_dir():
                for path in sorted(RUNS_DIR.glob("*.jsonl"), key=lambda p: p.stat().st_mtime, reverse=True):
                    try:
                        with path.open(encoding="utf-8", errors="replace") as fh:
                            events = sum(1 for line in fh if line.strip())
                    except OSError:
                        events = 0
                    runs.append({"name": path.name, "events": events, "mtime": path.stat().st_mtime})
            return self._json(runs)

        if parts.path == "/api/events":
            name = (query.get("run") or [""])[0]
            start = int((query.get("from") or ["0"])[0])
            # Containment check: never read outside the runs dir, whatever the caller sends.
            target = (RUNS_DIR / name).resolve()
            if not name or RUNS_DIR.resolve() not in target.parents or not target.is_file():
                return self._json([])
            out = []
            with target.open(encoding="utf-8", errors="replace") as fh:
                for index, event in enumerate(iter_events(fh)):
                    if index < start:
                        continue
                    kind, detail = classify(event)
                    out.append({"kind": kind, "detail": detail})
            return self._json(out)

        self._send(404, b"not found", "text/plain")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--port", type=int, default=8790)
    ap.add_argument("--runs-dir", default=None)
    args = ap.parse_args()

    global RUNS_DIR
    if args.runs_dir:
        RUNS_DIR = Path(args.runs_dir).expanduser()
    RUNS_DIR.mkdir(parents=True, exist_ok=True)

    server = ThreadingHTTPServer(("127.0.0.1", args.port), Handler)
    print(f"Citadel: http://127.0.0.1:{args.port}   runs: {RUNS_DIR}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
