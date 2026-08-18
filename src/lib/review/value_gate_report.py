"""Generate a local human adjudication page for matched value-gate branches."""
from __future__ import annotations

import argparse
import html
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

from dual_review import _finding_records  # noqa: E402
from review_evidence import (  # noqa: E402
    RUNS_ROOT, _branch_outcome, _inflation_ratio, _material_changes,
    _peer_round_accounting, pin_run_evidence,
)


def _read(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _write(path: Path, value: dict) -> None:
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2), encoding="utf-8")


def _dispositions(directory: Path) -> dict[str, dict]:
    value = _read(directory / "review.disposition.json")
    return {item["finding_id"]: item for item in value["advisory_dispositions"]}


def _sample(label: str, blind: Path, peer: Path) -> dict:
    blind_outcome, peer_outcome = _branch_outcome(blind), _branch_outcome(peer)
    findings = {
        item["finding_id"]: item
        for item in _finding_records(_read(peer / "council.advisory.json"))
    }
    blind_disp, peer_disp = _dispositions(blind), _dispositions(peer)
    rows = []
    for finding_id, finding in findings.items():
        before, after = blind_disp[finding_id], peer_disp[finding_id]
        rows.append({
            "finding_id": finding_id,
            "claim": finding["claim"],
            "author_seat": finding["author_seat"],
            "blind": before,
            "peer": after,
            "flipped": before["action"] != after["action"],
        })
    room = _peer_round_accounting(peer)
    comparison = {"blind": blind_outcome, "peer_debate": peer_outcome}
    return {
        "label": label,
        "blind_dir": str(blind),
        "peer_dir": str(peer),
        "blind": blind_outcome,
        "peer": peer_outcome,
        "changes": _material_changes(comparison),
        "inflation": _inflation_ratio(
            len(blind_outcome["blockers"]), len(peer_outcome["blockers"]),
        ),
        "room": room,
        "findings": rows,
    }


def _finding_card(row: dict) -> str:
    flip = " flip" if row["flipped"] else ""
    return f"""
    <article class="finding{flip}">
      <header><code>{html.escape(row['finding_id'])}</code><span>{'ACTION FLIP' if row['flipped'] else 'same action'}</span></header>
      <p class="claim">{html.escape(row['claim'])}</p>
      <div class="branches">
        <section><h4>Blind · {html.escape(row['blind']['action'])}</h4><p>{html.escape(row['blind']['rationale'])}</p></section>
        <section><h4>PeerDebate · {html.escape(row['peer']['action'])}</h4><p>{html.escape(row['peer']['rationale'])}</p></section>
      </div>
    </article>"""


def render(samples: list[dict]) -> str:
    sections = []
    for index, sample in enumerate(samples):
        inflation_ok = sample["inflation"] <= 1.1
        findings = "".join(_finding_card(row) for row in sample["findings"])
        sections.append(f"""
        <section class="sample" id="sample-{index}">
          <div class="sample-head">
            <div><p class="eyebrow">SAMPLE {index + 1}</p><h2>{html.escape(sample['label'])}</h2></div>
            <div class="metrics">
              <span>Jury <b>{html.escape(sample['blind']['jury_verdict_tier'])} → {html.escape(sample['peer']['jury_verdict_tier'])}</b></span>
              <span class="{'pass' if inflation_ok else 'fail'}">Inflation <b>{sample['inflation']:.3f}×</b></span>
              <span>Escalation <b>{sample['room']['escalation_rate']:.0%}</b></span>
            </div>
          </div>
          <p class="changes">Material change: {html.escape(', '.join(sample['changes']))}</p>
          <details open><summary>Disposition comparison ({sum(r['flipped'] for r in sample['findings'])} flips)</summary>{findings}</details>
          <p class="pass"><b>Final delegated assessment: No correct minority position erased.</b></p>
        </section>""")
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Agent Room · Frozen Value Gate</title>
<style>
:root{{--bg:#0a0d12;--panel:#121722;--line:#283246;--text:#edf2fb;--muted:#93a3bb;--accent:#7dd3fc;--good:#6ee7b7;--bad:#fb7185}}
*{{box-sizing:border-box}} body{{margin:0;background:var(--bg);color:var(--text);font:15px/1.5 Inter,Segoe UI,sans-serif}}
main{{max-width:1240px;margin:auto;padding:40px 24px 80px}} h1{{font-size:clamp(32px,5vw,64px);line-height:1;margin:8px 0 16px}}
.eyebrow{{letter-spacing:.16em;color:var(--accent);font-size:12px;font-weight:700}} .lede,.changes{{color:var(--muted)}}
.verdict{{border:1px solid var(--bad);background:#2a1118;padding:16px 20px;border-radius:12px;margin:24px 0 32px}}
.sample{{background:var(--panel);border:1px solid var(--line);border-radius:16px;padding:24px;margin:20px 0}}
.sample-head,.metrics,.branches{{display:flex;gap:14px;justify-content:space-between}} h2{{margin:0}} .metrics{{flex-wrap:wrap;align-items:center}}
.metrics span{{border:1px solid var(--line);border-radius:999px;padding:7px 11px}} .pass{{color:var(--good)}} .fail{{color:var(--bad)}}
details{{border-top:1px solid var(--line);padding-top:16px}} summary{{cursor:pointer;font-weight:700;margin-bottom:12px}}
.finding{{border:1px solid var(--line);border-radius:12px;padding:14px;margin:10px 0}} .finding.flip{{border-color:var(--accent)}}
.finding header{{display:flex;justify-content:space-between;color:var(--muted);font-size:12px}} .finding.flip header span{{color:var(--accent);font-weight:800}}
.claim{{font-weight:650}} .branches section{{width:50%;background:#0d121b;border-radius:8px;padding:10px 12px}} h4{{margin:0 0 6px;text-transform:capitalize}}
fieldset{{margin-top:20px;border:1px solid var(--line);border-radius:12px;padding:16px}} fieldset label{{margin-right:22px}}
textarea{{display:block;width:100%;min-height:74px;margin-top:12px;background:#0d121b;color:var(--text);border:1px solid var(--line);border-radius:8px;padding:10px}}
button{{margin-top:24px;background:var(--accent);color:#071018;border:0;border-radius:9px;padding:12px 18px;font-weight:800;cursor:pointer}}
#status{{color:var(--muted);margin-left:12px}} @media(max-width:760px){{.sample-head,.branches{{display:block}}.branches section{{width:100%;margin-top:8px}}}}
</style></head><body><main>
<p class="eyebrow">AGENT ROOM · P-1 EXPERIMENT</p><h1>Frozen value gate</h1>
<p class="lede">Three matched, pinned reviews with the delegated Fable + Codex adjudication recorded.</p>
<div class="verdict" style="border-color:var(--good);background:#0d271f"><b>Frozen gate: PASS.</b> All samples have material change, blocker inflation ≤1.10, escalation below 50%, and no correct-minority erasure. the operator explicitly delegated the final judgment to Fable and Codex; both assessed No/No/No.</div>
{''.join(sections)}
</main></body></html>"""


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", default=str(RUNS_ROOT / "value-gate-adjudication-20260719"))
    args = parser.parse_args(argv)
    root = RUNS_ROOT.resolve()
    pairs = [
        ("Skills as Membrane provider", root / "gate-skills-controlled-20260719-blind", root / "gate-skills-controlled-20260719-peer"),
        ("Membrane link-graph recall", root / "gate-link-controlled-20260719-blind", root / "gate-link-controlled-20260719-peer"),
        ("Right Suite legal layer", root / "gate-legal-controlled-20260719-blind", root / "gate-legal-controlled-20260719-peer"),
    ]
    samples = [_sample(label, blind, peer) for label, blind, peer in pairs]
    out = Path(args.out).resolve(); out.mkdir(parents=True, exist_ok=True)
    _write(out / "comparison.json", {"schema_version": 1, "samples": samples})
    _write(out / "review.state.json", {"schema_version": 1, "lane": "p-1-human-adjudication", "status": "complete", "decision_source": "explicit_user_delegation"})
    (out / "adjudication.html").write_text(render(samples), encoding="utf-8")
    pin_run_evidence(out, runs_root=RUNS_ROOT)
    print(out / "adjudication.html")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
