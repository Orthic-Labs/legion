"""Provider interface + shared types."""
from __future__ import annotations
from dataclasses import dataclass, field, asdict
from typing import Optional, Protocol


@dataclass
class JurorResult:
    juror_id: str
    provider: str
    model: str
    verdict: str = "ERROR"
    score: int = 0
    top_concern: str = ""
    scores: dict = field(default_factory=dict)
    answers: dict = field(default_factory=dict)
    blockers: list = field(default_factory=list)
    raw_response: str = ""
    parsed_ok: bool = False
    latency_ms: int = 0
    degraded: bool = False
    fallback_used: bool = False
    error: Optional[str] = None
    cache_hit: bool = False
    lens: Optional[str] = None  # added 2026-07-14 per Fable review
    call_count: int = 0
    usage: dict = field(default_factory=dict)
    usage_complete: bool = True

    def to_dict(self) -> dict:
        return asdict(self)


class ProviderError(Exception):
    """Raised on transport / auth / quota failures. Engine catches and falls through."""
    def __init__(self, message: str, status: Optional[int] = None, is_quota: bool = False):
        super().__init__(message)
        self.status = status
        self.is_quota = is_quota


class Provider(Protocol):
    """All providers expose .call() with the same signature."""
    name: str

    def call(
        self,
        model: str,
        system: str,
        user: str,
        max_tokens: int = 2048,
        images: Optional[list] = None,   # list[{"mime","b64","source"}] or None
    ) -> str:
        """Return raw assistant text. Raise ProviderError on failure.

        When `images` is provided, the provider sends them as multipart/inline
        content alongside the text. Each item: {"mime": "image/png", "b64": "...",
        "source": "<path>"}. Providers that don't support vision raise
        ProviderError if images are non-empty.
        """
        ...
