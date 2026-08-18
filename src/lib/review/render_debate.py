"""Render a council debate as a threaded conversation.

Reads the artifacts written by `dual_review.py --rebuttal` and emits one
self-contained HTML file: a chronological thread of blind position ->
PeerDebate contest -> typed peer reply, so the exchange reads as an argument
rather than three reports stacked in one page.

SCOPE — this is a *visual reference* for the P0 room watch page, not a component
it can import. The P0 page is Rust-served with a live SSE data source; what
carries over is the thread layout, seat-card shape, and audit-strip vocabulary,
deliberately reimplemented there. Nothing here is on SampleApp's dependency path.
See docs/plans/2026-07-14-agent-room-architecture.md.

    py -3.11 render_debate.py <review-dir> [-o out.html]
"""
from __future__ import annotations

import argparse
import html
import json
import statistics
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "lib"))
from pyio import ensure_utf8_stdio  # noqa: E402
ensure_utf8_stdio()


def _blocker_text(blocker) -> str:
    if isinstance(blocker, dict):
        return str(blocker.get("text", ""))
    return str(blocker)


def _blocker_tier(blocker) -> str:
    return str(blocker.get("tier", "")) if isinstance(blocker, dict) else ""


def _esc(value) -> str:
    return html.escape(str(value if value is not None else ""))


def _dispersion(seats: list[dict]) -> float:
    scores = [j.get("score") or 0 for j in seats if j.get("parsed_ok")]
    return round(statistics.pstdev(scores), 2) if len(scores) > 1 else 0.0


def _kind(blocker) -> str:
    if isinstance(blocker, dict) and isinstance(blocker.get("contest"), dict):
        return "contest"
    if isinstance(blocker, dict) and isinstance(blocker.get("resolution"), dict):
        choice = blocker["resolution"].get("choice")
        return choice if choice in {"concede", "sustain"} else "response"
    text = _blocker_text(blocker)
    upper = text.strip().upper()
    if upper.startswith("CONTEST:"):
        return "contest"
    if upper.startswith("RESPONSE:"):
        if "CONCEDE" in upper:
            return "concede"
        if "SUSTAIN" in upper:
            return "sustain"
        return "response"
    return "finding"


def _blocker_list(juror: dict) -> str:
    rows = []
    for blocker in juror.get("blockers") or []:
        text = _blocker_text(blocker)
        tier = _blocker_tier(blocker)
        kind = _kind(blocker)
        tier_html = f'<span class="tier">{_esc(tier)}</span>' if tier else ""
        rows.append(f'<li class="b {kind}">{tier_html}{_esc(text)}</li>')
    for text in juror.get("discarded_adoptions") or []:
        rows.append(
            f'<li class="b discarded"><span class="tier">cut</span>{_esc(text)}'
            f'<span class="note">unsupported adoption — discarded before synthesis</span></li>'
        )
    return "".join(rows) or '<li class="b empty">(none)</li>'


def _msg(seat: str, phase: str, juror: dict, meta: str = "") -> str:
    """One message bubble in the thread."""
    if not juror.get("parsed_ok"):
        return (
            f'<article class="msg failed"><header><b>{_esc(seat)}</b>'
            f'<span class="phase">{_esc(phase)}</span>'
            f'<span class="badge err">no position</span></header>'
            f'<p class="err-text">{_esc(juror.get("error") or "unparsed response")}</p>'
            f'<p class="note">This seat is silent, not agreeing — its objections, if any, '
            f'were never raised.</p></article>'
        )
    return (
        f'<article class="msg"><header><b>{_esc(seat)}</b>'
        f'<span class="phase">{_esc(phase)}</span>'
        f'<span class="verdict">{_esc(juror.get("verdict"))}</span>'
        f'<span class="score">{_esc(juror.get("score"))}</span>{meta}</header>'
        f'<p class="concern">{_esc(juror.get("top_concern"))}</p>'
        f'<ul>{_blocker_list(juror)}</ul></article>'
    )


CSS = """
:root{--bg:#F7F3EC;--fg:#211C18;--muted:#6E665F;--line:#E2DAD1;--card:#FFFDF8;
--accent:#0C6AA5;--warn:#B3261E;--ok:#1B5E20;--cut:#8A8070}
@media(prefers-color-scheme:dark){:root{--bg:#111722;--fg:#F4EFE7;--muted:#A39A91;
--line:#2D3037;--card:#171E2B;--accent:#3FA3DE;--warn:#F2B8B5;--ok:#7DD37D;--cut:#7A736B}}
*{box-sizing:border-box}body{margin:0;padding:2rem;background:var(--bg);color:var(--fg);
font:15px/1.55 ui-sans-serif,system-ui,-apple-system,Segoe UI,sans-serif;max-width:60rem}
h1{font-size:1.35rem;margin:0 0 .25rem}.sub{color:var(--muted);margin:0 0 1.25rem}
.strip{display:flex;flex-wrap:wrap;gap:.6rem;margin-bottom:1.5rem}
.metric{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:.6rem .9rem;min-width:10rem}
.metric b{display:block;font-size:1.35rem;line-height:1.15}
.metric span{color:var(--muted);font-size:.78rem}
.metric.flag{border-color:var(--warn)}.metric.flag b{color:var(--warn)}
.metric.good{border-color:var(--ok)}.metric.good b{color:var(--ok)}
h2{font-size:.8rem;text-transform:uppercase;letter-spacing:.06em;color:var(--muted);
margin:1.75rem 0 .6rem;border-top:1px solid var(--line);padding-top:.9rem}
.msg{background:var(--card);border:1px solid var(--line);border-radius:12px;
padding:.85rem 1.1rem;margin:0 0 .7rem}
.msg.reply{margin-left:2rem;border-left:3px solid var(--accent)}
.msg.failed{border-style:dashed;opacity:.85}
.msg header{display:flex;align-items:baseline;gap:.6rem;flex-wrap:wrap;margin-bottom:.4rem}
.msg header b{font-size:.95rem}
.phase{color:var(--muted);font-size:.72rem;text-transform:uppercase;letter-spacing:.05em}
.verdict{font-size:.8rem}.score{color:var(--accent);font-size:.8rem}
.badge{font-size:.72rem;border:1px solid var(--line);border-radius:99px;padding:.05rem .5rem}
.badge.err{border-color:var(--warn);color:var(--warn)}
.badge.to{border-color:var(--accent);color:var(--accent)}
.concern{margin:.2rem 0 .5rem}
ul{margin:0;padding-left:1.15rem}li{margin:.22rem 0}
.tier{display:inline-block;min-width:1.8rem;color:var(--muted);font-size:.75rem}
.b.contest{color:var(--accent);font-weight:500}
.b.concede{color:var(--ok);font-weight:500}
.b.sustain{color:var(--warn);font-weight:500}
.b.discarded{color:var(--cut);text-decoration:line-through}
.b.discarded .note{display:block;text-decoration:none;font-size:.72rem;color:var(--muted)}
.b.empty,.note{color:var(--muted)}
.err-text{color:var(--warn);margin:.2rem 0}
.note{font-size:.78rem;margin:.2rem 0 0}
footer{margin-top:2rem;color:var(--muted);font-size:.78rem;border-top:1px solid var(--line);padding-top:1rem}
"""


def _audit(payload: dict, reb_jurors: list[dict]) -> dict:
    """Use the persisted audit; recompute for runs predating it.

    A missing measurement must never render as compliance.
    """
    audit = payload.get("contest_audit")
    if audit and "answering_seats" in audit:
        return audit
    answering = [j for j in reb_jurors if j.get("parsed_ok")]
    contesting = sum(
        1 for j in answering
        if any((isinstance(b, dict) and isinstance(b.get("contest"), dict))
               or _blocker_text(b).strip().upper().startswith("CONTEST:")
               for b in (j.get("blockers") or []))
    )
    return {
        "contesting_seats": contesting,
        "answering_seats": len(answering),
        "total_seats": len(reb_jurors),
        "failed_seats": [j.get("juror_id") for j in reb_jurors if not j.get("parsed_ok")],
        "herding_suspected": bool(answering) and contesting < len(answering),
        "fully_compliant": bool(answering) and contesting == len(answering)
                           and len(answering) == len(reb_jurors),
    }


def render(review_dir: Path) -> str:
    payload = json.loads((review_dir / "council.advisory.json").read_text(encoding="utf-8"))
    blind = payload.get("jurors", [])
    reb = payload.get("rebuttal", {}).get("jurors", [])
    resp = payload.get("response", {}).get("jurors", [])
    reb_by = {j.get("juror_id"): j for j in reb}
    resp_by = {j.get("juror_id"): j for j in resp}

    audit = _audit(payload, reb)
    res_audit = payload.get("resolution_audit") or {}
    n_blind = sum(len(j.get("blockers") or []) for j in blind if j.get("parsed_ok"))
    n_reb = sum(len(j.get("blockers") or []) for j in reb if j.get("parsed_ok"))
    inflation = (n_reb / n_blind) if n_blind else 0.0
    failed = audit.get("failed_seats") or []
    open_contests = res_audit.get("open_contests")

    metrics = [
        ("Dispersion", f"{_dispersion(blind)} &rarr; {_dispersion(reb)}",
         "score spread, blind &rarr; PeerDebate", None),
        ("Contested", f"{audit.get('contesting_seats','?')} / {audit.get('answering_seats','?')}",
         "seats that contested a peer",
         "flag" if audit.get("herding_suspected") else "good"),
        ("Inflation", f"&times;{inflation:.2f}", "blocker count vs blind",
         "flag" if inflation > 1.15 else None),
    ]
    if resp:
        metrics.append((
            "Resolved",
            f"{res_audit.get('conceded_count',0)}c / {res_audit.get('sustained_count',0)}s",
            "contests conceded / sustained",
            "flag" if open_contests else "good",
        ))
    if failed:
        metrics.append(("Failed seats", str(len(failed)),
                        html.escape(", ".join(str(f) for f in failed)), "flag"))
    if open_contests:
        metrics.append(("Open contests", str(open_contests),
                        "unanswered — blocks seal under the two-exit rule", "flag"))

    strip = "".join(
        f'<div class="metric{" " + cls if cls else ""}"><b>{value}</b>'
        f"<span>{label} — {note}</span></div>"
        for label, value, note, cls in metrics
    )

    thread = ['<h2>Round 1 — blind positions (seats could not see each other)</h2>']
    thread += [_msg(j.get("juror_id"), "position", j) for j in blind]

    if reb:
        thread.append('<h2>Round 2 — PeerDebate (peers revealed)</h2>')
        for j in blind:
            seat = j.get("juror_id")
            if seat in reb_by:
                thread.append(_msg(seat, "PeerDebate", reb_by[seat]))
        for j in reb:
            if j.get("juror_id") not in {b.get("juror_id") for b in blind}:
                thread.append(_msg(j.get("juror_id"), "PeerDebate", j))

    if resp:
        thread.append('<h2>Round 3 — PeerDebate replies</h2>')
        for j in resp:
            targets = ", ".join(str(t) for t in (j.get("answering_contests") or []))
            badge = f'<span class="badge to">answering {_esc(targets)}</span>' if targets else ""
            thread.append(
                _msg(j.get("juror_id"), "PeerDebateReply", j, badge).replace(
                    '<article class="msg"', '<article class="msg reply"', 1
                ).replace('<article class="msg failed"', '<article class="msg reply failed"', 1)
            )

    return (
        f'<!doctype html><meta charset="utf-8"><title>Council debate — {_esc(review_dir.name)}</title>'
        f"<style>{CSS}</style><h1>Council debate</h1>"
        f'<p class="sub">{_esc(payload.get("skill"))} · {_esc(review_dir.name)} · '
        f"{len(blind)} seats · {'3 rounds' if resp else '2 rounds' if reb else '1 round'}</p>"
        f'<div class="strip">{strip}</div>{"".join(thread)}'
        f"<footer>Batch review, not a live room: seats never saw each other in real time. Each was "
        f"re-run once per round with the relevant peer material appended, so no seat's later "
        f"reasoning leaked into another's. Live rooms are P0/P1 in "
        f"docs/plans/2026-07-14-agent-room-architecture.md.</footer>"
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Render a council debate as HTML.")
    parser.add_argument("review_dir", help="directory containing council.advisory.json")
    parser.add_argument("-o", "--output", help="output path (default: <review-dir>/debate.html)")
    args = parser.parse_args(argv)

    review_dir = Path(args.review_dir)
    if not (review_dir / "council.advisory.json").is_file():
        parser.error(f"no council.advisory.json in {review_dir}")

    out = Path(args.output) if args.output else review_dir / "debate.html"
    out.write_text(render(review_dir), encoding="utf-8")
    sys.stdout.write(f"{out}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
