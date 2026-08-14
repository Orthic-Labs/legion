"""Focused callable-contract regression for public Tasklist entrypoint."""
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
evals = json.loads((ROOT / "evals/evals.json").read_text())
assert evals["skill"] == "tasklist"
assert sum(len(evals[key]) for key in ("should_trigger", "should_not_trigger", "output_quality", "safety", "pressure", "compatibility")) == 8
skill = (ROOT / "SKILL.md").read_text()
assert "dispatch-validator" in skill and "Dispatch" in skill and "Handoff" in skill
assert "dispatch-validator" in (ROOT / "scripts/validate-tasklist.py").read_text()

example = ROOT / "examples/tasklist-authority.packet.json"
result = subprocess.run([sys.executable, str(ROOT / "scripts/validate-tasklist.py"), str(example), "--receipt-mode", "verify"], capture_output=True, text=True)
assert result.returncode == 0, result.stdout + result.stderr
assert (ROOT / "examples/tasklist-authority.packet.receipt.json").is_file()

with tempfile.TemporaryDirectory() as directory:
    folder = Path(directory)
    route = folder / "sage-architect.json"
    route.write_text("{}", encoding="utf-8")
    packet = folder / "packet.json"
    packet.write_text(json.dumps({
        "schemaVersion": 1, "kind": "legion-authority-dispatch", "packetType": "sage",
        "sourceRevision": "abcdef0", "promptDigest": "sha256:" + "0" * 64,
        "modelRouting": {"modelTier": "FRONTIER", "workerProfile": "strict", "routingRationale": "tasklist"},
        "routeBundle": {"path": str(route), "digest": "sha256:" + hashlib.sha256(route.read_bytes()).hexdigest()},
    }), encoding="utf-8")
    result = subprocess.run([sys.executable, str(ROOT / "scripts/validate-tasklist.py"), str(packet)], capture_output=True, text=True)
    assert result.returncode == 0, result.stdout + result.stderr
    assert packet.with_suffix(".receipt.json").is_file()
