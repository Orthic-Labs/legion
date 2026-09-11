#!/usr/bin/env python3
"""Persistent SEO operating-state helper.

Stores intervention baselines, deployment verification, outcome reviews, and compact
operator briefs without pretending to schedule itself. Host schedulers invoke this
script or `/seo next`; this file owns deterministic state only.
"""
from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path

SCHEMA_VERSION = 1


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def load_state(path: Path) -> dict:
    if not path.exists():
        return {"schema_version": SCHEMA_VERSION, "interventions": [], "runs": []}
    data = json.loads(path.read_text(encoding="utf-8"))
    if data.get("schema_version") != SCHEMA_VERSION:
        raise SystemExit(f"unsupported state schema: {data.get('schema_version')}")
    data.setdefault("interventions", [])
    data.setdefault("runs", [])
    return data


def save_state(path: Path, state: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(state, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    tmp.replace(path)


def find_intervention(state: dict, intervention_id: str) -> dict:
    for row in state["interventions"]:
        if row.get("id") == intervention_id:
            return row
    raise SystemExit(f"unknown intervention: {intervention_id}")


def cmd_start(args, state):
    if any(x.get("id") == args.id for x in state["interventions"]):
        raise SystemExit(f"intervention already exists: {args.id}")
    row = {
        "id": args.id,
        "created_at": utc_now(),
        "target": args.target,
        "hypothesis": args.hypothesis,
        "primary_metric": args.metric,
        "evaluation_after": args.evaluate_after,
        "guardrails": args.guardrail or [],
        "baseline": json.loads(args.baseline) if args.baseline else {},
        "status": "planned",
        "deployment": None,
        "outcomes": [],
    }
    state["interventions"].append(row)
    return row


def cmd_deploy(args, state):
    row = find_intervention(state, args.id)
    row["status"] = "deployed_verified" if args.verified else "deployed_unverified"
    row["deployment"] = {
        "recorded_at": utc_now(),
        "identity": args.identity,
        "verified": bool(args.verified),
        "evidence": args.evidence,
    }
    return row


def cmd_outcome(args, state):
    row = find_intervention(state, args.id)
    outcome = {
        "recorded_at": utc_now(),
        "verdict": args.verdict,
        "metrics": json.loads(args.metrics) if args.metrics else {},
        "evidence": args.evidence,
        "confounders": args.confounder or [],
    }
    row["outcomes"].append(outcome)
    if args.verdict in {"improved", "worsened", "neutral", "inconclusive"}:
        row["status"] = "evaluated"
    return outcome


def cmd_run(args, state):
    run = {
        "recorded_at": utc_now(),
        "cadence": args.cadence,
        "property": args.property,
        "primary_action": args.primary_action,
        "critical": args.critical or [],
        "watch": args.watch or [],
        "evidence": args.evidence or [],
    }
    state["runs"].append(run)
    return run


def cmd_brief(args, state):
    if not state["runs"]:
        return {"status": "no_runs"}
    run = state["runs"][-1]
    pending = [x for x in state["interventions"] if x.get("status") not in {"evaluated", "cancelled"}]
    return {
        "run": run,
        "open_interventions": [
            {
                "id": x["id"],
                "target": x["target"],
                "status": x["status"],
                "evaluation_after": x.get("evaluation_after"),
            }
            for x in pending
        ],
    }


def main():
    ap = argparse.ArgumentParser(description="SEO intervention and recurring-run state")
    ap.add_argument("--state", default=".seo/search-ops.json")
    sub = ap.add_subparsers(dest="command", required=True)

    s = sub.add_parser("start")
    s.add_argument("--id", required=True)
    s.add_argument("--target", required=True)
    s.add_argument("--hypothesis", required=True)
    s.add_argument("--metric", required=True)
    s.add_argument("--evaluate-after", required=True)
    s.add_argument("--guardrail", action="append")
    s.add_argument("--baseline", help="JSON object")

    s = sub.add_parser("deploy")
    s.add_argument("--id", required=True)
    s.add_argument("--identity", required=True)
    s.add_argument("--verified", action="store_true")
    s.add_argument("--evidence")

    s = sub.add_parser("outcome")
    s.add_argument("--id", required=True)
    s.add_argument("--verdict", choices=["improved", "worsened", "neutral", "inconclusive", "immature"], required=True)
    s.add_argument("--metrics", help="JSON object")
    s.add_argument("--evidence")
    s.add_argument("--confounder", action="append")

    s = sub.add_parser("run")
    s.add_argument("--cadence", choices=["daily", "weekly", "monthly", "quarterly", "deploy"], required=True)
    s.add_argument("--property", required=True)
    s.add_argument("--primary-action")
    s.add_argument("--critical", action="append")
    s.add_argument("--watch", action="append")
    s.add_argument("--evidence", action="append")

    sub.add_parser("brief")

    args = ap.parse_args()
    path = Path(args.state)
    state = load_state(path)
    fn = globals()[f"cmd_{args.command.replace('-', '_')}"]
    result = fn(args, state)
    if args.command != "brief":
        save_state(path, state)
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
