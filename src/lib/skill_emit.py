"""skill_emit — the ONE durable-knowledge output path for bucket-A skills (Skill Output Contract).

A skill builds a `concepts` list and calls `emit_knowledge`. That writes an OKF bundle (md + YAML
frontmatter + link graph) via okf.py, then best-effort pushes each concept into the memory engine so
it is recallable immediately. No skill writes its own markdown/json or talks to the engine directly.

  concept = {"name","type","title"?,"description"?,"tags"?,"body","links"?}

CLI:  py -3.11 skill_emit.py cortex <repo>   # understanding.json -> OKF bundle + ingest
"""
from __future__ import annotations

import io
import hashlib
import json
import os
import re
import subprocess
import sys
import urllib.error
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))
_REPO_ROOT = HERE.parents[1]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))
import okf  # noqa: E402  same dir — call emit_bundle in-process, no subprocess/Node
from memory.runtime_config import crypt_port  # noqa: E402
from tools.hooks.lib.workspace import resolve_workspace_root  # noqa: E402

WS = resolve_workspace_root(__file__)
CRYPT_BIN = Path(os.environ.get("CRYPT_BIN", str(WS / "tools/bin" / ("crypt.exe" if os.name == "nt" else "crypt"))))
CRYPT_DB = Path(os.environ.get("CRYPT_DB", str(WS / "tools/.cache/memory/crypt-engine.db")))
ORT_DYLIB = Path(os.environ.get("ORT_DYLIB_PATH", str(WS / "tools/bin" / ("onnxruntime.dll" if os.name == "nt" else "libonnxruntime.dylib"))))
API_TOKEN_FILE = Path(os.environ.get(
    "CRYPT_API_TOKEN_FILE", str(CRYPT_DB.parent / "api-token")))


def _memory_name(md_path: Path) -> str:
    safe = re.sub(r"[^A-Za-z0-9_.:-]+", "-", md_path.stem).strip("-")
    return safe[:120] or "concept"


def _scope_for_path(md_path: Path) -> str:
    parts = md_path.resolve().parts
    if ".agent" in parts:
        root = Path(*parts[:parts.index(".agent")])
    else:
        root = md_path.resolve().parent
    return str(root).replace(":", "-").replace("\\", "-").replace("/", "-").strip("-") or "global"


def _crypt_env() -> dict:
    env = {**os.environ, "CRYPT_DB": str(CRYPT_DB), "ORT_DYLIB_PATH": str(ORT_DYLIB)}
    env.setdefault("CRYPT_PORT", str(crypt_port(env)))
    env.setdefault("HF_HOME", str(WS / "tools/.cache/fastembed"))
    env.setdefault("CRYPT_API_TOKEN_FILE", str(API_TOKEN_FILE))
    return env


def _api_token() -> str | None:
    try:
        token = API_TOKEN_FILE.read_text(encoding="utf-8").strip()
    except OSError:
        return None
    return token or None


_CLIENT_TOKEN = re.compile(r"^[a-z0-9][a-z0-9._:-]{0,79}$")


def _detect_writer_client(env=os.environ) -> str:
    explicit = str(env.get("CRYPT_CLIENT") or "").strip().lower()
    if explicit:
        if not _CLIENT_TOKEN.fullmatch(explicit):
            raise ValueError("invalid CRYPT_CLIENT attribution token")
        return explicit
    base = str(env.get("ANTHROPIC_BASE_URL") or "").strip().lower()
    if "127.0.0.1:8801" in base or "localhost:8801" in base:
        return "claudemm"
    if str(env.get("CODEX_THREAD_ID") or "").strip():
        return "codex"
    if str(env.get("CLAUDECODE") or "").strip():
        return "claude"
    return "manual"


def _http_ingest_batch(
    md_paths: list[Path], *, producer: str, record_type: str
) -> list[dict]:
    """Persist one emitted bundle through one model call and one SQLite transaction."""
    if not md_paths:
        return []

    try:
        client = _detect_writer_client()
    except ValueError:
        return [
            {"status": "failed", "transport": "local", "reason": "invalid_client"}
            for _path in md_paths
        ]

    canonical_items = []
    for md_path in md_paths:
        content = md_path.read_text(encoding="utf-8")
        canonical_items.append({
            "name": _memory_name(md_path),
            "scope": _scope_for_path(md_path),
            "content": content,
            "tier": "Semantic",
            "artifact_family": "skill_output",
            "producer": producer,
            "record_type": record_type,
        })
    canonical = json.dumps(
        canonical_items,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )
    digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    batch_id = f"skill-{digest}"
    session_id = f"skill-job-{digest[:32]}"
    trace_id = f"skill-trace-{digest[:32]}"
    items = []
    for index, canonical_item in enumerate(canonical_items):
        item_digest = hashlib.sha256(
            json.dumps(
                canonical_item,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=False,
            ).encode("utf-8")
        ).hexdigest()
        items.append({
            "item_id": f"item-{index:04d}-{item_digest[:16]}",
            **canonical_item,
            "client": client,
            "session_id": session_id,
            "trace_id": trace_id,
        })

    body = json.dumps(
        {"batch_id": batch_id, "items": items}, ensure_ascii=False
    ).encode("utf-8")
    headers = {"Content-Type": "application/json"}
    token = _api_token()
    if token:
        headers["Authorization"] = f"Bearer {token}"
    port = _crypt_env()["CRYPT_PORT"]
    request = urllib.request.Request(
        f"http://127.0.0.1:{port}/v1/memories:batch",
        data=body,
        headers=headers,
        method="POST",
    )
    unavailable = {
        "status": "unavailable",
        "transport": "http",
        "reason": "service_unavailable",
    }
    invalid = {
        "status": "failed",
        "transport": "http",
        "reason": "invalid_response",
    }
    try:
        with urllib.request.urlopen(request, timeout=20) as response:
            payload = json.loads(response.read().decode("utf-8"))
            receipts = payload.get("receipts")
            if (
                response.status not in (200, 201)
                or payload.get("batch_id") != batch_id
                or payload.get("complete") is not True
                or not isinstance(receipts, list)
                or len(receipts) != len(items)
                or payload.get("inserted", 0) + payload.get("duplicates", 0)
                != len(items)
            ):
                return [dict(invalid) for _ in items]
            statuses = {
                receipt.get("item_id"): receipt.get("status")
                for receipt in receipts
                if isinstance(receipt, dict)
            }
            accepted = {"inserted", "updated", "duplicate"}
            if (
                set(statuses) != {item["item_id"] for item in items}
                or any(status not in accepted for status in statuses.values())
            ):
                return [dict(invalid) for _ in items]
            return [
                {"status": "persisted", "transport": "http"}
                for _ in items
            ]
    except urllib.error.HTTPError as error:
        failed = {
            "status": "failed",
            "transport": "http",
            "reason": f"http_{error.code}",
        }
        return [dict(failed) for _ in items]
    except (urllib.error.URLError, TimeoutError, OSError):
        return [dict(unavailable) for _ in items]
    except (UnicodeDecodeError, json.JSONDecodeError):
        return [dict(invalid) for _ in items]


def _cli_ingest(md_path: Path, *, producer: str, record_type: str) -> dict:
    """Use the canonical CLI only when no resident service accepted the connection."""
    try:
        result = subprocess.run(
            [
                str(CRYPT_BIN),
                "put",
                _memory_name(md_path),
                "--scope",
                _scope_for_path(md_path),
                "--file",
                str(md_path),
                "--artifact-family",
                "skill_output",
                "--producer",
                producer,
                "--record-type",
                record_type,
            ],
            timeout=20,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            env=_crypt_env(),
        )
    except subprocess.TimeoutExpired:
        return {"status": "failed", "transport": "cli", "reason": "timeout"}
    except OSError:
        return {"status": "failed", "transport": "cli", "reason": "unavailable"}
    if result.returncode != 0:
        return {"status": "failed", "transport": "cli", "reason": f"exit_{result.returncode}"}
    return {"status": "persisted", "transport": "cli"}


def _ingest_batch(
    md_paths: list[Path], *, producer: str, record_type: str
) -> list[dict]:
    outcomes = _http_ingest_batch(
        md_paths, producer=producer, record_type=record_type
    )
    if outcomes and all(outcome["status"] == "unavailable" for outcome in outcomes):
        return [
            _cli_ingest(md_path, producer=producer, record_type=record_type)
            for md_path in md_paths
        ]
    return outcomes


def emit_knowledge(
    concepts: list[dict],
    out_dir: Path,
    compress: bool = False,
    *,
    producer: str = "skill_emit",
    record_type: str = "skill_concept",
) -> dict:
    """Write the OKF bundle for a skill's durable knowledge (in-process via okf.emit_bundle), then
    ingest it into the engine. compress defaults OFF — concepts are already distilled, and compression
    loads a heavy LLMLingua model; opt in only for verbose bodies."""
    out_dir = Path(out_dir).resolve()  # absolute so the engine infers the full scope slug, not a relative name
    out_dir.mkdir(parents=True, exist_ok=True)
    okf.emit_bundle(str(out_dir), concepts, compress=compress)
    emitted = [out_dir / f"{concept['name']}.md" for concept in concepts]
    emitted.append(out_dir / "index.md")
    outcomes = list(zip(
        emitted,
        _ingest_batch(emitted, producer=producer, record_type=record_type),
    ))
    persisted = sum(outcome["status"] == "persisted" for _, outcome in outcomes)
    failures = [
        {"file": path.name, "reason": outcome.get("reason", "unknown")}
        for path, outcome in outcomes
        if outcome["status"] != "persisted"
    ]
    transports: dict[str, int] = {}
    for _, outcome in outcomes:
        transport = outcome.get("transport", "unknown")
        transports[transport] = transports.get(transport, 0) + 1
    return {
        "okf_dir": str(out_dir),
        "concepts": len(concepts),
        "files": len(emitted),
        "persisted": persisted,
        "failed": len(failures),
        "complete": not failures,
        "transports": transports,
        "failures": failures,
    }


# ── cortex: understanding.json -> concepts ────────────────────────────────
CORTEX_DIMENSIONS = ("architecture", "interfaces", "health", "contract", "security", "solid")


class CortexArtifactError(ValueError):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


def _cortex_dimensions(repo: Path) -> dict[str, dict]:
    artifact = Path(repo) / ".agent" / "understanding.json"
    if not artifact.is_file():
        raise CortexArtifactError("missing_understanding", "understanding.json is missing")
    try:
        with io.open(artifact, encoding="utf-8") as handle:
            data = json.load(handle)
    except (OSError, json.JSONDecodeError) as error:
        raise CortexArtifactError("invalid_json", f"understanding.json is invalid: {error}") from error
    if not isinstance(data, dict):
        raise CortexArtifactError("invalid_shape", "understanding.json must contain an object")

    nested_raw = data.get("dimensions")
    if nested_raw is not None and not isinstance(nested_raw, dict):
        raise CortexArtifactError("invalid_shape", "understanding.json dimensions must be an object")
    nested = {
        name: nested_raw[name]
        for name in CORTEX_DIMENSIONS
        if isinstance(nested_raw, dict) and name in nested_raw
    }
    top_level = {name: data[name] for name in CORTEX_DIMENSIONS if name in data}
    conflicts = [
        name for name in CORTEX_DIMENSIONS
        if name in nested and name in top_level
        and json.dumps(nested[name], sort_keys=True, separators=(",", ":"))
        != json.dumps(top_level[name], sort_keys=True, separators=(",", ":"))
    ]
    if conflicts:
        raise CortexArtifactError(
            "conflicting_dimensions",
            f"top-level and nested understanding dimensions disagree: {', '.join(conflicts)}",
        )
    dimensions = {name: nested.get(name, top_level.get(name)) for name in CORTEX_DIMENSIONS}
    dimensions = {name: value for name, value in dimensions.items() if value is not None}
    if not dimensions:
        raise CortexArtifactError("no_eligible_dimensions", "understanding.json has no supported dimensions")
    invalid = [name for name, dimension in dimensions.items() if not isinstance(dimension, dict)]
    if invalid:
        raise CortexArtifactError(
            "invalid_dimension",
            f"understanding.json dimensions must be objects: {', '.join(invalid)}",
        )
    return dimensions


def _render_dimension(name: str, dim: dict) -> str:
    lines = [dim.get("summary", "").strip(), ""]
    for key, val in dim.items():
        if key in ("schemaVersion", "generatedAt", "dimension", "summary") or not isinstance(val, list):
            continue
        if not val:
            continue
        lines.append(f"## {key}")
        for item in val:
            if isinstance(item, dict):
                head = item.get("name") or item.get("layer") or item.get("title") or item.get("id") or ""
                rest = "; ".join(f"{k}: {v}" for k, v in item.items() if k not in ("name", "layer", "title", "id") and v)
                ref = item.get("file") or item.get("path") or ""
                lines.append(f"- **{head}** — {rest}" + (f" (`{ref}`)" if ref else ""))
            else:
                lines.append(f"- {item}")
        lines.append("")
    return "\n".join(lines).strip()


def cortex_concepts(repo: Path) -> list[dict]:
    slug = str(Path(repo).resolve().name)
    dims = _cortex_dimensions(repo)
    concepts = []
    for name, dim in dims.items():
        concepts.append({
            "name": f"{slug}-{name}",
            "type": name,  # architecture | interfaces | health | contract | security | solid
            "title": f"{slug} — {name}",
            "description": (dim.get("summary") or "")[:240],
            "tags": ["cortex", slug],
            "body": _render_dimension(name, dim),
            "links": [],
        })

    # Discrete debt concepts — so memory RECALL surfaces architectural debt proactively instead of
    # burying it in the architecture blob: one type:risk per uncovered flow, one type:contradiction
    # per CODE-FELL-SHORT (an agent that did not do what a plan said).
    arch = dims.get("architecture") or {}
    gaps = arch.get("coverageGaps") if isinstance(arch, dict) else None
    for i, gap in enumerate(gaps or []):
        if not isinstance(gap, dict):
            continue
        flow = gap.get("flow") or gap.get("name") or f"gap-{i}"
        concepts.append({
            "name": f"{slug}-risk-{i}",
            "type": "risk",
            "title": f"{slug} — uncovered flow: {flow}"[:120],
            "description": f"{gap.get('status', '')}: {gap.get('impact') or ''}".strip(": ")[:240],
            "tags": ["cortex", slug, "risk", "coverage-gap"],
            "body": "; ".join(f"{k}: {v}" for k, v in gap.items() if v),
            "links": [f"{slug}-architecture"],
        })

    recon_path = Path(repo) / ".agent" / "reconcile.json"
    if recon_path.is_file():
        try:
            with io.open(recon_path, encoding="utf-8") as handle:
                recon = json.load(handle)
        except (OSError, json.JSONDecodeError):
            recon = None
        entries = recon if isinstance(recon, list) else (recon.get("items") if isinstance(recon, dict) else None)
        for i, entry in enumerate(entries or []):
            if not isinstance(entry, dict) or entry.get("verdict") != "CODE-FELL-SHORT":
                continue
            claim = entry.get("claim") or ""
            concepts.append({
                "name": f"{slug}-contradiction-{i}",
                "type": "contradiction",
                "title": f"{slug} — CODE-FELL-SHORT: {claim}"[:120],
                "description": f"doc says: {claim}"[:240],
                "tags": ["cortex", slug, "contradiction", "code-fell-short"],
                "body": "; ".join(f"{k}: {v}" for k, v in entry.items() if k != "decision" and v),
                "links": [f"{slug}-architecture"],
            })

    return concepts


def emit_cortex(repo: Path) -> dict:
    try:
        concepts = cortex_concepts(repo)
    except CortexArtifactError as error:
        return {"error": str(error), "code": error.code, "repo": str(repo)}
    return emit_knowledge(
        concepts,
        Path(repo) / ".agent" / "okf",
        producer="cortex",
        record_type="cortex_concept",
    )


# ── generic: a markdown report -> OKF concepts (one per ## section) ──────────
def _slug(s: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", s.lower()).strip("-")[:60] or "x"


def report_concepts(md: str, type_: str, slug: str) -> list[dict]:
    """Split a skill's markdown report into OKF concepts: the preamble (+ H1) is the overview, each
    `## ` section is a concept. Reusable by every report-style knowledge skill (audit/research/seo/…)."""
    parts = re.split(r"(?m)^## +", md)
    out = []
    pre = parts[0].strip()
    if pre:
        h1 = re.search(r"(?m)^# +(.+)", pre)
        title = h1.group(1).strip() if h1 else f"{slug} {type_} overview"
        first = next((ln for ln in pre.splitlines() if ln.strip() and not ln.startswith("#")), title)
        out.append({"name": f"{slug}-{type_}-overview", "type": type_, "title": title,
                    "description": first[:240], "tags": [type_, slug], "body": pre, "links": []})
    for sec in parts[1:]:
        head = sec.splitlines()[0].strip()
        out.append({"name": f"{slug}-{type_}-{_slug(head)}", "type": type_, "title": head,
                    "description": head[:240], "tags": [type_, slug], "body": "## " + sec.strip(), "links": []})
    return out


def emit_report(report_path: Path, type_: str, repo: Path) -> dict:
    md = io.open(report_path, encoding="utf-8").read()
    slug = Path(repo).resolve().name
    concepts = report_concepts(md, type_, slug)
    if not concepts:
        return {"error": "empty report", "report": str(report_path)}
    producer = _slug(type_)
    return emit_knowledge(
        concepts,
        Path(repo) / ".agent" / "okf",
        producer=producer,
        record_type=f"{producer}_concept",
    )


def main(argv=None) -> int:
    import argparse

    p = argparse.ArgumentParser(prog="skill_emit")
    sub = p.add_subparsers(dest="cmd", required=True)
    bp = sub.add_parser("cortex"); bp.add_argument("repo")
    rp = sub.add_parser("report"); rp.add_argument("report"); rp.add_argument("--type", required=True); rp.add_argument("--repo", default=".")
    a = p.parse_args(argv)
    if a.cmd == "cortex":
        print(json.dumps(emit_cortex(Path(a.repo)), indent=2))
    elif a.cmd == "report":
        print(json.dumps(emit_report(Path(a.report), a.type, Path(a.repo)), indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
