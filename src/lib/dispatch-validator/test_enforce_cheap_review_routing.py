#!/usr/bin/env python3
"""Smoke checks for local cost-routing validator."""

import hashlib
import json
import subprocess
import sys
import tempfile
from pathlib import Path


HERE = Path(__file__).resolve().parent
ENTRY = HERE / "enforce_cheap_review_routing.py"


def packet(root: Path) -> tuple[Path, dict]:
    subprocess.run(["git", "init", "-q"], cwd=root, check=True)
    subprocess.run(["git", "config", "user.email", "routing-test@example.test"], cwd=root, check=True)
    subprocess.run(["git", "config", "user.name", "Routing Test"], cwd=root, check=True)
    prompt = root / "captured-prompt.txt"; prompt.write_text("exact captured routing prompt", encoding="utf-8")
    route = root / "sage-adjudication.json"; route.write_text("{}", encoding="utf-8")
    subprocess.run(["git", "add", "."], cwd=root, check=True)
    subprocess.run(["git", "commit", "-qm", "fixture source"], cwd=root, check=True)
    revision = subprocess.run(["git", "rev-parse", "HEAD"], cwd=root, check=True, capture_output=True, text=True).stdout.strip()
    value = {"schemaVersion": 1, "kind": "legion-authority-dispatch", "packetType": "sage",
             "repositoryRoot": str(root), "sourceRevision": revision,
             "promptArtifact": str(prompt), "promptDigest": "sha256:" + hashlib.sha256(prompt.read_bytes()).hexdigest(),
             "modelRouting": {"modelTier": "CHEAP_STRICT", "workerProfile": "strict", "routingRationale": "bounded execution"},
             "routeBundle": {"path": str(route), "digest": "sha256:" + hashlib.sha256(route.read_bytes()).hexdigest()}}
    path = root / "packet.json"; path.write_text(json.dumps(value), encoding="utf-8")
    return path, value


def main() -> int:
    with tempfile.TemporaryDirectory() as directory:
        path, value = packet(Path(directory))
        result = subprocess.run([sys.executable, str(ENTRY), str(path)], capture_output=True, text=True)
        assert result.returncode == 0, result.stdout + result.stderr
        value["modelRouting"]["workerProfile"] = "standard"; path.write_text(json.dumps(value), encoding="utf-8")
        result = subprocess.run([sys.executable, str(ENTRY), str(path)], capture_output=True, text=True)
        assert result.returncode == 1 and "CHEAP_STRICT requires strict" in result.stdout
        del value["modelRouting"]["routingRationale"]; path.write_text(json.dumps(value), encoding="utf-8")
        result = subprocess.run([sys.executable, str(ENTRY), str(path)], capture_output=True, text=True)
        assert result.returncode == 1 and "modelTier, workerProfile, routingRationale" in result.stdout
    print("PASS: cost routing requires contract fields & CHEAP_STRICT doctrine")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
