"""Typed P-1 Agent Room protocol fixture.

This is deliberately not the P0 room service.  It is the small, local
correctness harness that must pass before the Rust/SQLite/HTTP service is
allowed to start.  State transitions are driven by typed method arguments;
peer prose is stored as untrusted data and never parsed into control events.
"""
from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
from typing import Any
from urllib.parse import urlparse


PEER_FINDING_FIELDS = (
    "finding_id",
    "claim",
    "severity",
    "rationale",
    "evidence_refs",
    "proposed_change",
    "confidence",
)

PHASES = (
    "Open",
    "Positions",
    "PeerDebate",
    "Dispositions",
    "AuthorReview",
    "Escalation",
    "Voting",
    "Verdict",
    "AbortedFallback",
)

_TRANSITIONS = {
    "Open": {"Positions"},
    "Positions": {"PeerDebate"},
    "PeerDebate": {"Dispositions"},
    "Dispositions": {"AuthorReview", "AbortedFallback"},
    "AuthorReview": {"Escalation", "Voting"},
    "Escalation": {"Voting"},
    "Voting": {"Verdict"},
    "Verdict": set(),
    "AbortedFallback": set(),
}

_CAPABILITIES = {
    "review": frozenset({
        "join", "status", "next", "post", "leave", "findings", "contests",
        "dispositions", "resolutions", "rulings", "motions", "votes",
    }),
    "debate": frozenset({
        "join", "status", "next", "post", "leave", "findings", "contests",
        "dispositions", "resolutions", "rulings", "motions", "votes",
    }),
    "worksplit": frozenset({"join", "status", "next", "post", "leave", "tasks"}),
    "freeform": frozenset({"join", "status", "next", "post", "leave"}),
}


class ProtocolError(ValueError):
    """A fail-closed protocol rejection with a stable machine-readable code."""

    def __init__(self, code: str, detail: str = ""):
        self.code = code
        self.detail = detail
        super().__init__(f"{code}: {detail}" if detail else code)


def _canonical(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _stable_id(prefix: str, *parts: str) -> str:
    digest = _sha256_bytes("\x1f".join(parts).encode("utf-8"))[:20]
    return f"{prefix}_{digest}"


def derive_review_scope(disposition: dict, deferred: list[dict]) -> dict:
    """Return the only admissible initial review-scope motion payload."""
    normalized_deferred = sorted(
        copy.deepcopy(deferred),
        key=lambda item: (
            str(item.get("finding_id", "")),
            str(item.get("owner_phase", item.get("phase", ""))),
        ),
    )
    source = {
        "review_disposition": copy.deepcopy(disposition),
        "defer_to_phase": normalized_deferred,
    }
    digest = _sha256_bytes(_canonical(source).encode("utf-8"))
    return {
        "kind": "review_scope",
        "text": "Did the built phase prove the pinned Loop-1 obligations?",
        "scope_refs": [
            str(item.get("finding_id"))
            for item in normalized_deferred
            if item.get("finding_id")
        ],
        "scope_digest": digest,
        "source": source,
    }


def derive_review_scope_from_artifacts(
    disposition_path: str | Path,
    deferred_path: str | Path,
    *,
    workspace_root: str | Path,
) -> dict:
    """Derive scope from the persisted Loop-1 bytes and bind both SHA-256 receipts."""
    root = Path(workspace_root).resolve()
    paths = [Path(disposition_path).resolve(), Path(deferred_path).resolve()]
    for path in paths:
        try:
            path.relative_to(root)
        except ValueError as exc:
            raise ProtocolError("scope_artifact_outside_workspace", str(path)) from exc
        if not path.is_file():
            raise ProtocolError("scope_artifact_missing", str(path))
    disposition = json.loads(paths[0].read_text(encoding="utf-8"))
    deferred = json.loads(paths[1].read_text(encoding="utf-8"))
    if not isinstance(disposition, dict) or not isinstance(deferred, list):
        raise ProtocolError("scope_artifact_schema_invalid")
    derived = derive_review_scope(disposition, deferred)
    source_artifacts = [
        {
            "path": path.relative_to(root).as_posix(),
            "sha256": _sha256_bytes(path.read_bytes()),
        }
        for path in paths
    ]
    digest_source = {"source": derived["source"], "source_artifacts": source_artifacts}
    return {
        **derived,
        "scope_digest": _sha256_bytes(_canonical(digest_source).encode("utf-8")),
        "source_artifacts": source_artifacts,
    }


class RoomProtocol:
    """In-memory typed protocol used by P-1 adversarial fixtures."""

    def __init__(
        self,
        *,
        room_id: str,
        workspace_root: str | Path,
        seats: dict[str, dict],
        mode: str = "review",
        at_budget: str = "abstain",
    ):
        if mode not in _CAPABILITIES:
            raise ProtocolError("invalid_mode", mode)
        if at_budget not in {"abstain", "summarize-and-continue"}:
            raise ProtocolError("invalid_at_budget_behavior", at_budget)
        self.room_id = room_id
        self.workspace_root = Path(workspace_root).resolve()
        self.seats = copy.deepcopy(seats)
        self.mode = mode
        self.at_budget = at_budget
        self.phase = "Open"
        self.events: list[dict] = []
        self.findings: dict[str, dict] = {}
        self.contests: dict[str, dict] = {}
        self.dispositions: dict[str, dict] = {}
        self.receipts: dict[str, dict] = {}
        self.motions: dict[str, dict] = {}
        self.votes: dict[str, dict] = {}
        self.escalations: list[str] = []
        self._requests: dict[tuple[str, str], dict] = {}
        self._author_rewakes: dict[str, int] = {}
        self.sealed = False

    def _seat(self, actor: str) -> dict:
        seat = self.seats.get(actor)
        if not seat:
            raise ProtocolError("unknown_seat", actor)
        return seat

    def _require_role(self, actor: str, *roles: str) -> None:
        role = self._seat(actor).get("role")
        if role not in roles:
            raise ProtocolError("role_forbidden", f"{actor}:{role}")

    def _require_capability(self, capability: str) -> None:
        if capability not in _CAPABILITIES[self.mode]:
            raise ProtocolError("mode_forbidden", f"{capability} in {self.mode}")

    def _idempotent(
        self,
        *,
        actor: str,
        request_id: str,
        operation: str,
        payload: dict,
        apply,
    ):
        self._seat(actor)
        if not request_id or not isinstance(request_id, str):
            raise ProtocolError("request_id_required")
        key = (actor, request_id)
        canonical = _canonical({"operation": operation, "payload": payload})
        prior = self._requests.get(key)
        if prior:
            if prior["canonical"] != canonical:
                raise ProtocolError("request_id_conflict", request_id)
            return copy.deepcopy(prior["result"])
        result = apply()
        self._requests[key] = {"canonical": canonical, "result": copy.deepcopy(result)}
        return copy.deepcopy(result)

    def _event(self, *, actor: str, request_id: str, kind: str, **fields) -> dict:
        event = {
            "seq": len(self.events) + 1,
            "room_id": self.room_id,
            "seat_id": actor,
            "phase": self.phase,
            "request_id": request_id,
            "kind": kind,
            **fields,
        }
        self.events.append(event)
        return event

    def capabilities(self, seat_id: str) -> tuple[str, ...]:
        self._seat(seat_id)
        return tuple(sorted(_CAPABILITIES[self.mode]))

    def advance(self, *, actor: str, target: str, request_id: str) -> dict:
        self._require_role(actor, "moderator", "human")
        if target not in PHASES:
            raise ProtocolError("unknown_phase", target)
        if target in {"Voting", "Verdict"} and self.open_finding_ids():
            raise ProtocolError("open_findings", ",".join(self.open_finding_ids()))

        payload = {"target": target}

        def apply():
            if target not in _TRANSITIONS[self.phase]:
                raise ProtocolError("invalid_transition", f"{self.phase}->{target}")
            self.phase = target
            return self._event(actor=actor, request_id=request_id, kind="phase", target=target)

        return self._idempotent(
            actor=actor, request_id=request_id, operation="advance", payload=payload, apply=apply,
        )

    def post(
        self,
        *,
        actor: str,
        kind: str,
        body: str,
        request_id: str,
        reply_to: str | None = None,
        evidence_refs: list[str] | None = None,
        plumbing: dict | None = None,
    ) -> dict:
        self._require_capability("post")
        if kind not in {"position", "question", "evidence", "info"}:
            raise ProtocolError("invalid_post_kind", kind)
        if kind == "position" and self.phase != "Positions":
            raise ProtocolError("phase_forbidden", f"position in {self.phase}")
        payload = {
            "kind": kind,
            "body": body,
            "reply_to": reply_to,
            "evidence_refs": evidence_refs or [],
            # Plumbing participates in idempotency but never crosses the peer boundary.
            "plumbing": plumbing or {},
        }

        def apply():
            return self._event(
                actor=actor,
                request_id=request_id,
                kind=kind,
                body=str(body),
                reply_to=reply_to,
                evidence_refs=list(evidence_refs or []),
                untrusted=True,
            )

        return self._idempotent(
            actor=actor, request_id=request_id, operation="post", payload=payload, apply=apply,
        )

    def visible_events(self, seat_id: str, cursor: int = 0) -> list[dict]:
        self._seat(seat_id)
        visible = []
        for event in self.events:
            if event["seq"] <= cursor:
                continue
            if (
                self.phase == "Positions"
                and event.get("kind") == "position"
                and event.get("seat_id") != seat_id
            ):
                continue
            visible.append(copy.deepcopy(event))
        return visible

    def rejoin_view(self, seat_id: str, *, cursor: int) -> list[dict]:
        """Replay through the current visibility projection, never raw storage."""
        return self.visible_events(seat_id, cursor=cursor)

    def raise_finding(
        self,
        *,
        actor: str,
        claim: str,
        severity: str,
        rationale: str,
        evidence_refs: list[str],
        proposed_change: str,
        confidence: float,
        request_id: str,
    ) -> dict:
        self._require_capability("findings")
        if self.phase not in {"PeerDebate", "Dispositions"}:
            raise ProtocolError("phase_forbidden", f"finding in {self.phase}")
        payload = {
            "claim": claim,
            "severity": severity,
            "rationale": rationale,
            "evidence_refs": evidence_refs,
            "proposed_change": proposed_change,
            "confidence": confidence,
        }

        def apply():
            finding_id = _stable_id("finding", self.room_id, actor, request_id)
            finding = {
                "finding_id": finding_id,
                "author_seat": actor,
                **copy.deepcopy(payload),
                "status": "Open",
            }
            self.findings[finding_id] = finding
            self._event(
                actor=actor,
                request_id=request_id,
                kind="finding",
                finding_id=finding_id,
            )
            return finding

        return self._idempotent(
            actor=actor, request_id=request_id, operation="raise_finding", payload=payload, apply=apply,
        )

    def peer_findings(self, seat_id: str) -> list[dict]:
        self._seat(seat_id)
        return [
            {field: copy.deepcopy(finding.get(field)) for field in PEER_FINDING_FIELDS}
            for finding in self.findings.values()
            if finding.get("author_seat") != seat_id
        ]

    def contest(
        self,
        *,
        actor: str,
        finding_id: str,
        rationale: str,
        evidence_refs: list[str],
        request_id: str,
    ) -> dict:
        self._require_capability("contests")
        if finding_id not in self.findings:
            raise ProtocolError("unknown_finding", finding_id)
        payload = {"finding_id": finding_id, "rationale": rationale, "evidence_refs": evidence_refs}

        def apply():
            contest_id = _stable_id("contest", self.room_id, actor, request_id)
            contest = {
                "contest_id": contest_id,
                "finding_id": finding_id,
                "challenger_seat": actor,
                "rationale": rationale,
                "evidence_refs": list(evidence_refs),
            }
            self.contests[contest_id] = contest
            self._event(
                actor=actor, request_id=request_id, kind="contest",
                contest_id=contest_id, finding_id=finding_id,
            )
            return contest

        return self._idempotent(
            actor=actor, request_id=request_id, operation="contest", payload=payload, apply=apply,
        )

    def _workspace_locator(self, locator: str) -> tuple[Path, int | None]:
        path_text, line = locator, None
        if ":" in locator:
            maybe_path, maybe_line = locator.rsplit(":", 1)
            if maybe_line.isdigit():
                path_text, line = maybe_path, int(maybe_line)
        path = (self.workspace_root / path_text).resolve() if not Path(path_text).is_absolute() else Path(path_text).resolve()
        try:
            path.relative_to(self.workspace_root)
        except ValueError as exc:
            raise ProtocolError("receipt_outside_workspace", locator) from exc
        if not path.is_file():
            raise ProtocolError("receipt_missing", locator)
        if line is not None:
            if line < 1 or line > len(path.read_text(encoding="utf-8").splitlines()):
                raise ProtocolError("receipt_line_missing", locator)
        return path, line

    def add_receipt(
        self,
        *,
        actor: str,
        kind: str,
        locator: str,
        request_id: str,
        digest: str | None = None,
    ) -> dict:
        if kind not in {"file", "artifact", "measurement", "web", "scope_motion"}:
            raise ProtocolError("invalid_receipt_kind", kind)
        payload = {"kind": kind, "locator": locator, "digest": digest}

        def apply():
            if kind in {"file", "artifact"}:
                self._workspace_locator(locator)
            elif kind == "measurement":
                path, _ = self._workspace_locator(locator)
                actual = _sha256_bytes(path.read_bytes())
                if not digest or actual != digest:
                    raise ProtocolError("receipt_digest_mismatch", locator)
            elif kind == "web":
                parsed = urlparse(locator)
                if parsed.scheme not in {"http", "https"} or not parsed.netloc:
                    raise ProtocolError("invalid_source_url", locator)
            elif kind == "scope_motion":
                motion = self.motions.get(locator)
                if not motion or motion.get("kind") not in {"review_scope", "scope_amendment"}:
                    raise ProtocolError("unknown_scope_motion", locator)
                if not digest or digest != motion.get("scope_digest"):
                    raise ProtocolError("scope_digest_mismatch", locator)
            receipt_id = _stable_id("receipt", self.room_id, actor, request_id)
            receipt = {
                "receipt_id": receipt_id,
                "kind": kind,
                "locator": locator,
                "digest": digest,
            }
            self.receipts[receipt_id] = receipt
            self._event(
                actor=actor, request_id=request_id, kind="receipt", receipt_id=receipt_id,
            )
            return receipt

        return self._idempotent(
            actor=actor, request_id=request_id, operation="add_receipt", payload=payload, apply=apply,
        )

    def dispose(
        self,
        *,
        actor: str,
        finding_id: str,
        action: str,
        receipt_refs: list[str],
        request_id: str,
        reason_code: str | None = None,
    ) -> dict:
        self._require_capability("dispositions")
        self._require_role(actor, "implementer")
        if self.phase not in {"Dispositions", "AuthorReview"}:
            raise ProtocolError("phase_forbidden", f"dispose in {self.phase}")
        finding = self.findings.get(finding_id)
        if not finding:
            raise ProtocolError("unknown_finding", finding_id)
        if finding["status"] != "Open":
            raise ProtocolError("finding_not_open", finding_id)
        if action not in {"folded", "refuted"}:
            raise ProtocolError("invalid_disposition", action)
        if not receipt_refs:
            raise ProtocolError("receipt_required", finding_id)
        receipts = [self.receipts.get(receipt_id) for receipt_id in receipt_refs]
        if any(receipt is None for receipt in receipts):
            raise ProtocolError("unknown_receipt", finding_id)
        if action == "folded" and not any(receipt["kind"] == "artifact" for receipt in receipts):
            raise ProtocolError("fold_artifact_required", finding_id)
        if reason_code == "out_of_scope":
            initial = next((m for m in self.motions.values() if m["kind"] == "review_scope"), None)
            matching = any(
                receipt["kind"] == "scope_motion"
                and initial
                and receipt["locator"] == initial["motion_id"]
                and receipt["digest"] == initial["scope_digest"]
                for receipt in receipts
            )
            if not matching:
                raise ProtocolError("scope_receipt_required", finding_id)
        payload = {
            "finding_id": finding_id,
            "action": action,
            "receipt_refs": receipt_refs,
            "reason_code": reason_code,
        }

        def apply():
            disposition_id = _stable_id("disposition", self.room_id, actor, request_id)
            disposition = {
                "disposition_id": disposition_id,
                "finding_id": finding_id,
                "implementer_seat": actor,
                "action": action,
                "reason_code": reason_code,
                "receipt_refs": list(receipt_refs),
                "status": "Proposed",
            }
            self.dispositions[disposition_id] = disposition
            finding["status"] = "FoldProposed" if action == "folded" else "RefuteProposed"
            if self.findings and all(
                item["status"] in {"FoldProposed", "RefuteProposed", "Folded", "Refuted", "Recontested"}
                for item in self.findings.values()
            ):
                self.phase = "AuthorReview"
            self._event(
                actor=actor, request_id=request_id, kind="disposition",
                disposition_id=disposition_id, finding_id=finding_id,
            )
            return disposition

        return self._idempotent(
            actor=actor, request_id=request_id, operation="dispose", payload=payload, apply=apply,
        )

    def resolve(
        self,
        *,
        actor: str,
        disposition_id: str,
        choice: str,
        reason: str,
        evidence_refs: list[str],
        request_id: str,
    ) -> dict:
        self._require_capability("resolutions")
        if not isinstance(disposition_id, str):
            raise ProtocolError("one_disposition_required")
        disposition = self.dispositions.get(disposition_id)
        if not disposition:
            raise ProtocolError("unknown_disposition", disposition_id)
        finding = self.findings[disposition["finding_id"]]
        if actor != finding["author_seat"]:
            raise ProtocolError("author_required", actor)
        if actor == disposition["implementer_seat"]:
            raise ProtocolError("self_resolution_forbidden", actor)
        if self.phase not in {"AuthorReview", "Escalation"}:
            raise ProtocolError("phase_forbidden", f"resolve in {self.phase}")
        if choice not in {"accept", "recontest"}:
            raise ProtocolError("invalid_resolution", choice)
        payload = {
            "disposition_id": disposition_id,
            "choice": choice,
            "reason": reason,
            "evidence_refs": evidence_refs,
        }

        def apply():
            if disposition["status"] != "Proposed":
                raise ProtocolError("disposition_not_proposed", disposition_id)
            if choice == "accept":
                disposition["status"] = "Accepted"
                disposition["final_action"] = disposition["action"]
                disposition["final_receipt_refs"] = list(disposition["receipt_refs"])
                finding["status"] = "Folded" if disposition["action"] == "folded" else "Refuted"
            else:
                disposition["status"] = "Recontested"
                finding["status"] = "Recontested"
                if disposition_id not in self.escalations:
                    self.escalations.append(disposition_id)
                self.phase = "Escalation"
            return self._event(
                actor=actor, request_id=request_id, kind="resolution",
                disposition_id=disposition_id, choice=choice,
            )

        return self._idempotent(
            actor=actor, request_id=request_id, operation="resolve", payload=payload, apply=apply,
        )

    def rule(
        self,
        *,
        actor: str,
        disposition_id: str,
        action: str,
        reason: str,
        receipt_refs: list[str],
        request_id: str,
    ) -> dict:
        self._require_capability("rulings")
        self._require_role(actor, "human")
        disposition = self.dispositions.get(disposition_id)
        if not disposition:
            raise ProtocolError("unknown_disposition", disposition_id)
        if disposition["status"] != "Recontested":
            raise ProtocolError("disposition_not_recontested", disposition_id)
        if action not in {"folded", "refuted"}:
            raise ProtocolError("invalid_ruling", action)
        if not receipt_refs or any(receipt_id not in self.receipts for receipt_id in receipt_refs):
            raise ProtocolError("receipt_required", disposition_id)
        if action == "folded" and not any(
            self.receipts[receipt_id]["kind"] == "artifact" for receipt_id in receipt_refs
        ):
            raise ProtocolError("fold_artifact_required", disposition_id)
        payload = {
            "disposition_id": disposition_id,
            "action": action,
            "reason": reason,
            "receipt_refs": receipt_refs,
        }

        def apply():
            finding = self.findings[disposition["finding_id"]]
            disposition["status"] = "Ruled"
            disposition["ruling"] = {
                "human_seat": actor,
                "action": action,
                "reason": reason,
                "receipt_refs": list(receipt_refs),
            }
            disposition["final_action"] = action
            disposition["final_receipt_refs"] = list(receipt_refs)
            finding["status"] = "Folded" if action == "folded" else "Refuted"
            return self._event(
                actor=actor, request_id=request_id, kind="ruling",
                disposition_id=disposition_id, action=action,
            )

        return self._idempotent(
            actor=actor, request_id=request_id, operation="rule", payload=payload, apply=apply,
        )

    def create_review_scope(
        self,
        *,
        actor: str,
        disposition: dict,
        deferred: list[dict],
        supplied_digest: str,
        request_id: str,
    ) -> dict:
        self._require_capability("motions")
        self._require_role(actor, "moderator")
        if self.phase != "Open":
            raise ProtocolError("phase_forbidden", f"review_scope in {self.phase}")
        if any(motion["kind"] == "review_scope" for motion in self.motions.values()):
            raise ProtocolError("review_scope_exists")
        derived = derive_review_scope(disposition, deferred)
        if supplied_digest != derived["scope_digest"]:
            raise ProtocolError("scope_digest_mismatch")
        payload = {
            "disposition": disposition,
            "deferred": deferred,
            "supplied_digest": supplied_digest,
        }

        def apply():
            motion_id = _stable_id("motion", self.room_id, actor, request_id)
            motion = {
                "motion_id": motion_id,
                "moderator_seat": actor,
                "status": "Open",
                **derived,
            }
            self.motions[motion_id] = motion
            self._event(actor=actor, request_id=request_id, kind="motion", motion_id=motion_id)
            return motion

        return self._idempotent(
            actor=actor, request_id=request_id, operation="review_scope", payload=payload, apply=apply,
        )

    def create_review_scope_from_artifacts(
        self,
        *,
        actor: str,
        disposition_path: str,
        deferred_path: str,
        supplied_digest: str,
        request_id: str,
    ) -> dict:
        self._require_capability("motions")
        self._require_role(actor, "moderator")
        if self.phase != "Open":
            raise ProtocolError("phase_forbidden", f"review_scope in {self.phase}")
        if any(motion["kind"] == "review_scope" for motion in self.motions.values()):
            raise ProtocolError("review_scope_exists")
        disposition_file = (self.workspace_root / disposition_path).resolve()
        deferred_file = (self.workspace_root / deferred_path).resolve()
        derived = derive_review_scope_from_artifacts(
            disposition_file,
            deferred_file,
            workspace_root=self.workspace_root,
        )
        if supplied_digest != derived["scope_digest"]:
            raise ProtocolError("scope_digest_mismatch")
        payload = {
            "disposition_path": disposition_path,
            "deferred_path": deferred_path,
            "supplied_digest": supplied_digest,
        }

        def apply():
            motion_id = _stable_id("motion", self.room_id, actor, request_id)
            motion = {
                "motion_id": motion_id,
                "moderator_seat": actor,
                "status": "Open",
                **derived,
            }
            self.motions[motion_id] = motion
            self._event(actor=actor, request_id=request_id, kind="motion", motion_id=motion_id)
            return motion

        return self._idempotent(
            actor=actor,
            request_id=request_id,
            operation="review_scope_artifacts",
            payload=payload,
            apply=apply,
        )

    def vote(
        self,
        *,
        actor: str,
        motion_id: str,
        choice: str,
        reason: str,
        request_id: str,
    ) -> dict:
        self._require_capability("votes")
        if motion_id not in self.motions:
            raise ProtocolError("unknown_motion", motion_id)
        if self.phase != "Voting":
            raise ProtocolError("phase_forbidden", f"vote in {self.phase}")
        if self.open_finding_ids():
            raise ProtocolError("open_findings", ",".join(self.open_finding_ids()))
        payload = {"motion_id": motion_id, "choice": choice, "reason": reason}

        def apply():
            vote_id = _stable_id("vote", self.room_id, actor, request_id)
            vote = {
                "vote_id": vote_id,
                "motion_id": motion_id,
                "seat_id": actor,
                "choice": choice,
                "reason": reason,
            }
            self.votes[vote_id] = vote
            self._event(actor=actor, request_id=request_id, kind="vote", vote_id=vote_id)
            return vote

        return self._idempotent(
            actor=actor, request_id=request_id, operation="vote", payload=payload, apply=apply,
        )

    def amend_review_scope(
        self,
        *,
        actor: str,
        text: str,
        scope_refs: list[str],
        parent_digest: str,
        request_id: str,
    ) -> dict:
        self._require_capability("motions")
        self._require_role(actor, "human")
        if self.phase in {"Open", "Positions", "Verdict", "AbortedFallback"}:
            raise ProtocolError("phase_forbidden", f"scope amendment in {self.phase}")
        scope_chain = [
            motion
            for motion in self.motions.values()
            if motion.get("kind") in {"review_scope", "scope_amendment"}
        ]
        if not scope_chain:
            raise ProtocolError("review_scope_missing")
        current = scope_chain[-1]
        if parent_digest != current.get("scope_digest"):
            raise ProtocolError("scope_digest_mismatch")
        payload = {
            "text": text,
            "scope_refs": list(scope_refs),
            "parent_digest": parent_digest,
        }

        def apply():
            scope_digest = _sha256_bytes(_canonical(payload).encode("utf-8"))
            motion_id = _stable_id("motion", self.room_id, actor, request_id)
            motion = {
                "motion_id": motion_id,
                "kind": "scope_amendment",
                "text": text,
                "scope_refs": list(scope_refs),
                "parent_digest": parent_digest,
                "scope_digest": scope_digest,
                "human_seat": actor,
                "status": "Ruled",
            }
            self.motions[motion_id] = motion
            self._event(actor=actor, request_id=request_id, kind="motion", motion_id=motion_id)
            return motion

        return self._idempotent(
            actor=actor,
            request_id=request_id,
            operation="scope_amendment",
            payload=payload,
            apply=apply,
        )

    def tasks(self, *, actor: str, action: str, request_id: str) -> dict:
        self._require_capability("tasks")
        return self._idempotent(
            actor=actor,
            request_id=request_id,
            operation="tasks",
            payload={"action": action},
            apply=lambda: {"action": action, "tasks": []},
        )

    def record_timeout(self, *, actor: str, seat_id: str, request_id: str) -> dict:
        self._require_role(actor, "moderator", "human")
        seat = self._seat(seat_id)
        payload = {"seat_id": seat_id}

        def apply():
            if seat.get("role") == "implementer":
                self.phase = "AbortedFallback"
                return self._event(
                    actor=actor,
                    request_id=request_id,
                    kind="timeout",
                    seat_id=seat_id,
                    status="fallback_required",
                )
            pending = [
                disposition_id
                for disposition_id, disposition in self.dispositions.items()
                if self.findings[disposition["finding_id"]]["author_seat"] == seat_id
                and disposition["status"] == "Proposed"
            ]
            if not pending:
                raise ProtocolError("no_pending_author_review", seat_id)
            wakes = self._author_rewakes.get(seat_id, 0)
            if wakes == 0:
                self._author_rewakes[seat_id] = 1
                status = "rewake"
            else:
                for disposition_id in pending:
                    self.dispositions[disposition_id]["status"] = "Recontested"
                    finding = self.findings[self.dispositions[disposition_id]["finding_id"]]
                    finding["status"] = "Recontested"
                    if disposition_id not in self.escalations:
                        self.escalations.append(disposition_id)
                self.phase = "Escalation"
                status = "escalated"
            return self._event(
                actor=actor,
                request_id=request_id,
                kind="timeout",
                seat_id=seat_id,
                status=status,
            )

        return self._idempotent(
            actor=actor, request_id=request_id, operation="timeout", payload=payload, apply=apply,
        )

    def open_finding_ids(self) -> list[str]:
        return sorted(
            finding_id
            for finding_id, finding in self.findings.items()
            if finding.get("status") not in {"Folded", "Refuted"}
        )

    def metrics(self) -> dict:
        total = len(self.dispositions)
        rate = len(set(self.escalations)) / total if total else 0.0
        return {
            "total_dispositions": total,
            "escalated_dispositions": len(set(self.escalations)),
            "escalation_rate": rate,
            "failed_room": rate > 0.5,
            "at_budget": self.at_budget,
        }

    def ledger_payload(self) -> dict:
        """Return the typed, JSON-serializable ledger used by the Jury gate."""
        return {
            "schema_version": 1,
            "room_id": self.room_id,
            "mode": self.mode,
            "phase": self.phase,
            "findings": copy.deepcopy(list(self.findings.values())),
            "contests": copy.deepcopy(list(self.contests.values())),
            "dispositions": copy.deepcopy(list(self.dispositions.values())),
            "receipts": copy.deepcopy(list(self.receipts.values())),
            "motions": copy.deepcopy(list(self.motions.values())),
            "metrics": self.metrics(),
        }

    def status(self, seat_id: str) -> dict:
        self._seat(seat_id)
        return {
            "room_id": self.room_id,
            "seat_id": seat_id,
            "mode": self.mode,
            "phase": self.phase,
            "latest_visible_cursor": max(
                (event["seq"] for event in self.visible_events(seat_id)), default=0,
            ),
            "open_finding_ids": self.open_finding_ids(),
            "metrics": self.metrics(),
        }

    def seal(self, *, actor: str, request_id: str) -> dict:
        self._require_role(actor, "moderator", "human")
        if self.open_finding_ids():
            raise ProtocolError("open_findings", ",".join(self.open_finding_ids()))
        if self.phase != "Verdict":
            raise ProtocolError("phase_forbidden", f"seal in {self.phase}")

        def apply():
            self.sealed = True
            return self._event(actor=actor, request_id=request_id, kind="sealed")

        return self._idempotent(
            actor=actor, request_id=request_id, operation="seal", payload={}, apply=apply,
        )
