#!/usr/bin/env python3
"""Smoke checks for typed-tasklist compatibility entrypoint."""

import hashlib
import json
import subprocess
import sys
import tempfile
from pathlib import Path


HERE = Path(__file__).resolve().parent
ENTRY = HERE / "validate-tasklist.py"


def packet(root: Path) -> Path:
    subprocess.run(["git", "init", "-q"], cwd=root, check=True)
    subprocess.run(["git", "config", "user.email", "tasklist-test@example.test"], cwd=root, check=True)
    subprocess.run(["git", "config", "user.name", "Tasklist Test"], cwd=root, check=True)
    prompt = root / "captured-prompt.txt"; prompt.write_text("exact captured tasklist prompt", encoding="utf-8")
    route = root / "sage-adjudication.json"; route.write_text("{}", encoding="utf-8")
    subprocess.run(["git", "add", "."], cwd=root, check=True)
    subprocess.run(["git", "commit", "-qm", "fixture source"], cwd=root, check=True)
    revision = subprocess.run(["git", "rev-parse", "HEAD"], cwd=root, check=True, capture_output=True, text=True).stdout.strip()
    digest = "sha256:" + hashlib.sha256(route.read_bytes()).hexdigest()
    value = {"schemaVersion": 1, "kind": "legion-authority-dispatch", "packetType": "sage",
             "repositoryRoot": str(root), "sourceRevision": revision,
             "promptArtifact": str(prompt), "promptDigest": "sha256:" + hashlib.sha256(prompt.read_bytes()).hexdigest(),
             "modelRouting": {"modelTier": "FRONTIER", "workerProfile": "strict", "routingRationale": "material ownership adjudication"},
             "routeBundle": {"path": str(route), "digest": digest}}
    path = root / "packet.json"; path.write_text(json.dumps(value), encoding="utf-8")
    return path


def main() -> int:
    with tempfile.TemporaryDirectory() as directory:
        path = packet(Path(directory))
        result = subprocess.run([sys.executable, str(ENTRY), str(path)], capture_output=True, text=True)
        assert result.returncode == 0, result.stdout + result.stderr
        assert path.with_suffix(".receipt.json").is_file()
        value = json.loads(path.read_text(encoding="utf-8")); del value["modelRouting"]["routingRationale"]
        path.write_text(json.dumps(value), encoding="utf-8")
        result = subprocess.run([sys.executable, str(ENTRY), str(path)], capture_output=True, text=True)
        assert result.returncode == 1 and "modelTier, workerProfile, routingRationale" in result.stdout
    print("PASS: tasklist compatibility delegates typed validation & preserves failure exit")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
