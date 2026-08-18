"""Council engine — runs API jurors in parallel, parses verdicts, handles fallbacks.

Legacy escalation hooks remain for compatibility. The manual CLI-review lane (cli-review.py) was retired 2026-07-14.
"""
from __future__ import annotations
import json
import re
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Optional

import yaml

from providers import build_provider, JurorResult, ProviderError


ROOT = Path(__file__).parent


def _normalized_usage(usage: dict | None) -> dict:
    """Normalize provider usage without estimating missing token counts."""
    usage = usage or {}
    input_tokens = usage.get("input_tokens", usage.get("prompt_tokens"))
    output_tokens = usage.get("output_tokens", usage.get("completion_tokens"))
    total_tokens = usage.get("total_tokens")
    if total_tokens is None and input_tokens is not None and output_tokens is not None:
        total_tokens = int(input_tokens) + int(output_tokens)
    if input_tokens is None or output_tokens is None or total_tokens is None:
        return {}
    return {
        "input_tokens": int(input_tokens),
        "output_tokens": int(output_tokens),
        "total_tokens": int(total_tokens),
    }


def _accounting(results: list[JurorResult]) -> dict:
    usage = {"input_tokens": 0, "output_tokens": 0, "total_tokens": 0}
    for result in results:
        for key in usage:
            usage[key] += int(result.usage.get(key, 0))
    return {
        "calls": sum(result.call_count for result in results),
        "usage": usage,
        "usage_complete": all(result.usage_complete for result in results),
        "cache_hits": sum(1 for result in results if result.cache_hit),
    }


def _load_lenses() -> dict:
    """Load lens preambles from lenses.yaml. Cached per process."""
    lenses_path = ROOT / "lenses.yaml"
    if not lenses_path.is_file():
        return {}
    return yaml.safe_load(lenses_path.read_text(encoding="utf-8")) or {}


def _execution_units(jurors: list[dict], providers: dict) -> list[list[dict]]:
    """Return concurrent work units while preserving unsafe serialization."""
    grouped: dict[str, list[dict]] = {}
    for juror in jurors:
        grouped.setdefault(juror["provider"], []).append(juror)

    units: list[list[dict]] = []
    for provider_name, seats in grouped.items():
        if providers.get(provider_name, {}).get("parallel_safe", False):
            units.extend([[seat] for seat in seats])
        else:
            units.append(seats)
    return units


class Engine:
    def __init__(self, models_yaml: str | Path = None, cache_dir: str | Path = None,
                 lenses: dict | None = None):
        self.config_path = Path(models_yaml or ROOT / "models.yaml")
        from config import load_models_config
        self.config = load_models_config(self.config_path)
        self.prompt_version = int(self.config.get("prompt_version", 1))
        self.lenses = lenses if lenses is not None else _load_lenses()
        self.providers = {
            name: build_provider(name, cfg)
            for name, cfg in self.config["providers"].items()
        }
        # Cache import deferred so cache_dir override works
        from cache import Cache
        self.cache = Cache(cache_dir or ROOT / "cache")

    # ----- public -----

    def run(self, skill: str, user_input: str, flags: Optional[dict] = None,
            no_cache: bool = False, no_escalation: bool = True,
            enforce_packet: bool = True, panel_name: str = "jury",
            jurors_override: Optional[list[dict]] = None) -> dict:
        flags = flags or {}
        skill_cfg = self.config["skills"].get(skill)
        if not skill_cfg:
            raise ValueError(f"skill not found in models.yaml: {skill}")

        # Packet validation (locked 2026-07-14 — hard-fail when a packet is
        # PROVIDED and it's invalid). Backwards-compat: legacy callers
        # without a packet fence take the marked legacy path — `no_packet_fence`
        # is a disclosure marker, not a hard failure. (The original wiring
        # raised on it too, which crashed every fence-less legacy invocation
        # in direct contradiction of this comment — fixed 2026-07-14.)
        from packet import validate_packet, PacketValidationError, is_legacy_no_packet
        packet_validation = validate_packet(user_input, kind=skill)
        legacy_no_packet = is_legacy_no_packet(packet_validation)
        if packet_validation.errors and not legacy_no_packet:
            msg = (
                f"jury packet invalid for skill '{skill}': "
                f"{len(packet_validation.errors)} error(s), "
                f"{len(packet_validation.warnings)} warning(s). "
                f"First error: {packet_validation.errors[0]}"
            )
            if enforce_packet:
                raise PacketValidationError(msg)
            # Soft-fail path (callers that explicitly opted out via
            # enforce_packet=False). The errors stay in the result
            # envelope so the caller can surface them.
        has_packet = packet_validation.errors == [] and packet_validation.sections != {}

        rubric_path = ROOT / skill_cfg["rubric"]
        rubric = rubric_path.read_text(encoding="utf-8")

        is_vision = bool(skill_cfg.get("needs_vision_input"))
        system_prompt, user_prompt = self._build_prompts(
            rubric, user_input, is_vision, panel_name=panel_name
        )

        # Vision-input prep: skills marked needs_vision_input get image bytes
        # extracted from the user_input (paths to .png/.jpg/.mp4 etc.) and
        # encoded as base64 multipart parts for the providers that support it.
        vision_images: list[dict] = []
        if skill_cfg.get("needs_vision_input"):
            try:
                from vision_input import prepare_vision_payload
                vision_images = prepare_vision_payload(user_input)
            except Exception as ex:
                # Don't fail the whole review if vision prep breaks — degrade
                # to text-only and let jurors see the path strings.
                print(f"⚠ vision_input prep failed: {ex}", flush=True)
                vision_images = []

        # Unsafe same-provider seats (notably NIM free tier) stay in one serial
        # unit. Parallel-safe seats split into independent units even when they
        # share a provider; all units overlap across the panel.
        jurors_cfg = jurors_override or skill_cfg["jurors"]
        units = _execution_units(jurors_cfg, self.config["providers"])

        def run_unit(group: list[dict]) -> list[JurorResult]:
            return [
                self._run_juror(j, system_prompt, user_prompt, no_cache, vision_images, is_vision)
                for j in group
            ]

        results: list[JurorResult] = []
        with ThreadPoolExecutor(max_workers=max(1, len(units))) as pool:
            futures = [pool.submit(run_unit, unit) for unit in units]
            for fut in as_completed(futures):
                results.extend(fut.result())

        # Sort to stable order
        results.sort(key=lambda r: r.juror_id)

        # Escalation
        escalation_results: list[JurorResult] = []
        if not no_escalation:
            escalation_results = self._maybe_escalate(skill_cfg, system_prompt, user_prompt, results, flags)

        all_results = results + escalation_results
        return {
            "skill": skill,
            "panel": panel_name,
            "flags": flags,
            "rubric_file": str(rubric_path.relative_to(ROOT)),
            "prompt_version": self.prompt_version,
            "packet_validation": {
                "ok": packet_validation.ok,
                "errors": packet_validation.errors,
                "warnings": packet_validation.warnings,
                "section_count": len(packet_validation.sections),
                "has_packet": has_packet,
            },
            "jurors": [r.to_dict() for r in results],
            "escalation": [r.to_dict() for r in escalation_results],
            "accounting": _accounting(all_results),
            "synthesis": self._synthesize(skill, results, escalation_results),
        }

    # ----- internals -----

    def _build_prompts(self, rubric: str, user_input: str, is_vision: bool = False,
                        lens: Optional[str] = None,
                        panel_name: str = "jury") -> tuple[str, str]:
        """Build system + user prompts for one juror call.

        `lens` (optional) names a lens from lenses.yaml. When present, the
        lens preamble is prepended to the system prompt so the juror
        approaches the rubric from a specific angle. Same JSON schema; four
        different attack angles.
        """
        # Lens preamble substitution. Locked 2026-07-14.
        preamble_block = ""
        if lens and self.lenses.get(lens):
            lens_cfg = self.lenses[lens]
            lens_preamble = lens_cfg.get("preamble", "").rstrip()
            lens_question = lens_cfg.get("lens_question", "")
            preamble_block = f"\n\n# LENS ({lens})\n{lens_preamble}"
            if lens_question:
                preamble_block += (
                    f"\n\nIn addition to the rubric's shared questions, answer "
                    f"this lens-specific question in the output under "
                    f"`answers.{lens_question}` (≤200c)."
                )

        if is_vision:
            # Vision: rubric goes in SYSTEM; the user message stays minimal so the
            # IMAGE (appended to the user message) dominates attention. A long
            # rubric stuffed into the user text made VLMs ignore the real image
            # and hallucinate a different one.
            system = (
                rubric
                + preamble_block
                + "\n\nYou are reviewing the IMAGE attached to the user message. "
                "Output one minified JSON object matching the OUTPUT schema above. "
                "Every field MUST be grounded in what is visibly rendered in that image."
            )
            user = (
                "An image is attached to this message — review THIS screenshot.\n\n"
                "CONTEXT:\n" + user_input
            )
            return system, user
        # Terse: jurors output compact JSON only, no prose ceremony
        role = "Council adviser" if panel_name == "council" else "Jury juror"
        system = f"{role}. Follow rubric. Output JSON only." + preamble_block
        user = f"RUBRIC:\n{rubric}\n\nINPUT:\n{user_input}\n"
        return system, user

    def _run_juror(self, juror_cfg: dict, system: str, user: str, no_cache: bool, vision_images: list[dict] | None = None, is_vision: bool = False) -> JurorResult:
        chain = [(juror_cfg["provider"], juror_cfg["model"], False)] + [
            (fb["provider"], fb["model"], True) for fb in juror_cfg.get("fallbacks", [])
        ]
        # Per-juror vision gate: only jurors marked vision: true receive images.
        # Text-only jurors (e.g. brand_lens on llama-3.3-70b) read the path
        # strings + brand rules in the user prompt. This prevents 400s from
        # text-only models when a skill carries images.
        juror_can_vision = bool(juror_cfg.get("vision"))
        images_for_juror = vision_images if (juror_can_vision and vision_images) else None
        if images_for_juror and juror_cfg.get("max_images"):
            images_for_juror = images_for_juror[: int(juror_cfg["max_images"])]
        # Lens is locked into the cache key so two jurors with same
        # provider/model but different lenses don't return each other's verdict.
        lens = juror_cfg.get("lens")
        last_err: Optional[str] = None
        call_count = 0
        usage = {"input_tokens": 0, "output_tokens": 0, "total_tokens": 0}
        usage_complete = True
        for provider_name, model, is_fallback in chain:
            # Kill-switch: skip providers explicitly disabled in models.yaml.
            # Avoids burning retries on a provider that can only error (e.g.
            # Cerebras llama3.1-8b — 8K context < review prompts, plus free-tier
            # daily/queue 429s). Falls through to the next fallback in the chain.
            if self.config["providers"].get(provider_name, {}).get("disabled"):
                last_err = f"{provider_name} disabled in models.yaml"
                continue
            t0 = time.time()
            # Cache key includes a digest of vision images so a vision rerun
            # doesn't return a stale text-only verdict. Text-only jurors get
            # an empty digest so their cache stays compatible with prior runs.
            import hashlib as _hashlib
            vision_digest = ""
            if images_for_juror:
                h = _hashlib.sha256()
                for im in images_for_juror:
                    h.update(im.get("b64", "").encode("ascii", errors="ignore"))
                vision_digest = h.hexdigest()[:16]
            cache_key = self.cache.make_key(
                rubric="",  # rubric is part of `user` already
                user_input=f"{user}|vision:{vision_digest}|lens:{lens or 'default'}",
                provider=provider_name, model=model,
                prompt_version=self.prompt_version,
            )
            if not no_cache:
                cached = self.cache.get(cache_key)
                if cached and cached.get("parsed_ok"):
                    cached["juror_id"] = juror_cfg["id"]
                    cached["cache_hit"] = True
                    cached["fallback_used"] = is_fallback
                    cached["lens"] = lens
                    cached["call_count"] = 0
                    cached["usage"] = {}
                    cached["usage_complete"] = True
                    return JurorResult(**{k: v for k, v in cached.items() if k in JurorResult.__dataclass_fields__})

            provider = self.providers[provider_name]
            degraded = bool(self.config["providers"][provider_name].get("flag_degraded", False))
            try:
                # Per-seat budgets keep text panels fast while preserving the
                # larger vision allowance. Provider caps remain the hard wall.
                provider_cap = self.config["providers"].get(provider_name, {}).get("max_output_tokens", 8192)
                seat_cap = juror_cfg.get("max_tokens", 4096 if is_vision else 3072)
                _max_tokens = min(int(seat_cap), int(provider_cap))
                # Lens preamble substitution per juror (locked 2026-07-14).
                # Same rubric+input, different prompt framing. Cache key
                # already encodes lens, so different-lens prompts from the
                # same model don't collide.
                lens_block = ""
                if lens and self.lenses.get(lens):
                    lens_cfg = self.lenses[lens]
                    lens_preamble = lens_cfg.get("preamble", "").rstrip()
                    lens_question = lens_cfg.get("lens_question", "")
                    lens_block = f"\n\n# LENS ({lens})\n{lens_preamble}"
                    if lens_question:
                        lens_block += (
                            f"\n\nIn addition to the rubric's shared questions, "
                            f"answer this lens-specific question in the output "
                            f"under `answers.{lens_question}` (≤200c)."
                        )
                final_system = (system + lens_block).strip()
                call_system, call_user = self._provider_prompts(provider_name, final_system, user, is_vision)
                call_count += 1
                if hasattr(provider, "call_with_metadata"):
                    metadata = provider.call_with_metadata(
                        model, call_system, call_user,
                        max_tokens=_max_tokens, images=images_for_juror,
                    )
                    raw = metadata["text"]
                    observed = _normalized_usage(metadata.get("usage"))
                    if observed:
                        for key in usage:
                            usage[key] += observed[key]
                    else:
                        usage_complete = False
                else:
                    raw = provider.call(
                        model, call_system, call_user,
                        max_tokens=_max_tokens, images=images_for_juror,
                    )
                    usage_complete = False
                latency_ms = int((time.time() - t0) * 1000)
                parsed = self._parse_juror_json(raw)
                result = JurorResult(
                    juror_id=juror_cfg["id"],
                    provider=provider_name,
                    model=model,
                    verdict=parsed.get("verdict", "ERROR"),
                    score=int(parsed.get("score", 0) or 0),
                    top_concern=parsed.get("top_concern", ""),
                    scores=parsed.get("scores", {}) or {},
                    answers=parsed.get("answers", {}) or {},
                    blockers=parsed.get("blockers", []) or [],
                    raw_response=raw,
                    parsed_ok=parsed.get("_parsed_ok", False),
                    latency_ms=latency_ms,
                    degraded=degraded,
                    fallback_used=is_fallback,
                    lens=lens,
                    call_count=call_count,
                    usage=usage.copy(),
                    usage_complete=usage_complete,
                )
                if result.parsed_ok:
                    d = result.to_dict()
                    d["lens"] = lens
                    self.cache.set(cache_key, d)
                    return result

                d = result.to_dict()
                d["lens"] = lens
                self.cache.set_error(cache_key, d)
                last_err = f"{provider_name}/{model} returned unparseable JSON"
                continue
            except ProviderError as e:
                last_err = str(e)
                self.cache.set_error(cache_key, {"error": last_err, "provider": provider_name, "model": model})
                continue

        return JurorResult(
            juror_id=juror_cfg["id"],
            provider=chain[0][0], model=chain[0][1],
            verdict="ERROR", error=last_err or "all fallbacks exhausted",
            call_count=call_count,
            usage=usage,
            usage_complete=usage_complete,
        )

    @staticmethod
    def _parse_juror_json(raw):
        # Provider returned nothing (timeout, empty response, error path
        # that didn't raise). Surface as parse_error rather than crash.
        # Bug fixed 2026-05-05 — Kimi K2.6 timeouts were tipping the whole
        # council and bringing down auto-jury final QA.
        if raw is None:
            return {"_parsed_ok": False, "_raw": "", "_error": "juror returned None (timeout or empty response)"}
        if not isinstance(raw, str):
            raw = str(raw)
        # Strip reasoning traces from thinking models (qwen3.x, kimi-thinking) —
        # their <think>...</think> blocks contain braces that derail the greedy
        # JSON substring match below. Remove closed blocks; if an unclosed <think>
        # runs to EOF the reply was truncated mid-thought (raise max_tokens).
        s = re.sub(r"<think>.*?</think>", "", raw, flags=re.DOTALL).strip()
        s = re.sub(r"^<think>.*$", "", s, flags=re.DOTALL).strip()
        # Strip code fences if model added them despite instructions
        if s.startswith("```"):
            s = re.sub(r"^```(?:json)?\s*", "", s)
            s = re.sub(r"\s*```\s*$", "", s)
        # Find the first { and last } and try to parse
        try:
            obj = json.loads(s)
            obj["_parsed_ok"] = True
            return obj
        except Exception:
            # Try to extract JSON substring
            m = re.search(r"\{.*\}", s, re.DOTALL)
            if m:
                try:
                    obj = json.loads(m.group(0))
                    obj["_parsed_ok"] = True
                    return obj
                except Exception:
                    pass
        return {"_parsed_ok": False, "verdict": "PARSE_ERROR", "top_concern": s[:200]}

    @staticmethod
    def _provider_prompts(provider_name: str, system: str, user: str, is_vision: bool = False) -> tuple[str, str]:
        # Vision prompts are already structured (rubric in system, minimal user +
        # image); the NIM compaction below rewrites the user text and would strip
        # the grounding. Leave vision prompts untouched.
        if is_vision or provider_name != "nim":
            return system, user
        compact_system = "Return one minified JSON object only. No markdown. No prose."
        compact_user = (
            "Evaluate ARTIFACT using CRITERIA. Return JSON matching the output schema.\n\n"
            + user.replace("RUBRIC:\n", "CRITERIA:\n").replace("\n\nINPUT:\n", "\n\nARTIFACT:\n")
        )
        return compact_system, compact_user

    def _maybe_escalate(self, skill_cfg, system, user, results, flags) -> list[JurorResult]:
        rules = skill_cfg.get("escalation", [])
        triggered = []
        verdicts = [r.verdict for r in results if r.parsed_ok]
        is_split = len(set(verdicts)) > 1 if verdicts else False

        for rule in rules:
            trig = rule["trigger"]
            if trig == "always":
                triggered.append(rule)
            elif trig.startswith("flag."):
                flag_name = trig.split(".", 1)[1]
                if flags.get(flag_name):
                    triggered.append(rule)
            elif trig == "jury_split" and is_split:
                triggered.append(rule)

        if not triggered:
            return []

        # De-dup: same provider+model only fires once
        seen = set()
        out: list[JurorResult] = []
        for rule in triggered:
            k = (rule["provider"], rule["model"])
            if k in seen:
                continue
            seen.add(k)
            t0 = time.time()
            try:
                provider = self.providers[rule["provider"]]
                usage = {}
                usage_complete = True
                if hasattr(provider, "call_with_metadata"):
                    metadata = provider.call_with_metadata(
                        rule["model"], system, user, max_tokens=1024,
                    )
                    raw = metadata["text"]
                    usage = _normalized_usage(metadata.get("usage"))
                    usage_complete = bool(usage)
                else:
                    raw = provider.call(rule["model"], system, user, max_tokens=1024)
                    usage_complete = False
                parsed = self._parse_juror_json(raw)
                out.append(JurorResult(
                    juror_id=f"escalation:{rule['provider']}",
                    provider=rule["provider"], model=rule["model"],
                    verdict=parsed.get("verdict", "ERROR"),
                    score=int(parsed.get("score", 0) or 0),
                    top_concern=parsed.get("top_concern", ""),
                    scores=parsed.get("scores", {}) or {},
                    answers=parsed.get("answers", {}) or {},
                    blockers=parsed.get("blockers", []) or [],
                    raw_response=raw,
                    parsed_ok=parsed.get("_parsed_ok", False),
                    latency_ms=int((time.time() - t0) * 1000),
                    call_count=1,
                    usage=usage,
                    usage_complete=usage_complete,
                ))
            except ProviderError as e:
                out.append(JurorResult(
                    juror_id=f"escalation:{rule['provider']}",
                    provider=rule["provider"], model=rule["model"],
                    verdict="ERROR", error=str(e),
                    call_count=1,
                ))
        return out

    @staticmethod
    def _synthesize(skill: str, results, escalation) -> dict:
        all_results = list(results) + list(escalation)
        parsed = [r for r in all_results if r.parsed_ok]
        verdicts = [r.verdict for r in parsed]
        scores = [r.score for r in parsed if r.score > 0]
        from collections import Counter
        verdict_counts = Counter(verdicts)
        majority = verdict_counts.most_common(1)[0] if verdict_counts else ("UNDECIDED", 0)
        avg_score = round(sum(scores) / len(scores), 1) if scores else 0
        return {
            "majority_verdict": majority[0],
            "majority_count": f"{majority[1]}/{len(parsed)}" if parsed else "0/0",
            "avg_score": avg_score,
            "split": len(set(verdicts)) > 1,
            "any_degraded": any(r.degraded for r in all_results),
            "any_error": any(not r.parsed_ok for r in all_results),
        }
