"""Provider registry."""
from .base import JurorResult, ProviderError, Provider
from .openai_compat import OpenAICompatProvider
from .gemini import GeminiAPIProvider
from .subprocess_cli import SubprocessProvider
from .minimax_anthropic import MiniMaxAnthropicProvider


def build_provider(name: str, config: dict):
    t = config.get("type")
    if t == "openai_compat":
        return OpenAICompatProvider(name, config)
    if t == "minimax_anthropic":
        return MiniMaxAnthropicProvider(name, config)
    if t == "gemini_api":
        return GeminiAPIProvider(name, config)
    if t == "subprocess":
        return SubprocessProvider(name, config)
    raise ValueError(f"unknown provider type: {t}")


__all__ = [
    "JurorResult", "ProviderError", "Provider",
    "OpenAICompatProvider", "GeminiAPIProvider", "SubprocessProvider",
    "MiniMaxAnthropicProvider",
    "build_provider",
]
