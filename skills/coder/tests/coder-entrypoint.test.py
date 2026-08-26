"""Focused callable-contract regression for public Coder entrypoint."""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
evals = json.loads((ROOT / "evals/evals.json").read_text())
assert evals["skill"] == "coder"
assert sum(len(evals[key]) for key in ("should_trigger", "should_not_trigger", "output_quality", "safety", "pressure", "compatibility")) == 6
skill = (ROOT / "SKILL.md").read_text()
assert "coder-api-worker" in skill and "explicit opt-in" in skill and "Never transmit secrets" in skill
assert "pi --tools read,grep,find,ls -p" in skill
assert "coder-api-worker" in (ROOT / "scripts/api-worker.py").read_text()
assert json.loads((ROOT / "hooks/hooks.json").read_text()) == []
worker = (ROOT.parents[1] / "src/lib/coder-api-worker/api-worker.py").read_text()
assert 'PI_COMMAND = "pi"' in worker
assert '"--tools", ",".join(PI_TOOLS)' in worker
assert "subprocess.Popen" in worker and "shell=False" in worker
assert "coder.pi.receipt.v1" in worker
for obsolete in ("urllib.request", "PROVIDERS", "Authorization", "chat/completions"):
    assert obsolete not in worker
