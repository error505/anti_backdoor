from enum import Enum

from pydantic import BaseModel


class AiProvider(str, Enum):
    ANTHROPIC = "anthropic"
    OPENAI = "openai"


class ProviderOptions(BaseModel):
    """Choices offered in the UI. Models are suggestions; any model id may be typed in."""
    suggested_models: list[str]
    default_model: str
    effort_levels: list[str]
    default_effort: str


# Effort controls how long the model reasons: higher is more thorough, slower and pricier.
# Anthropic: output_config.effort. OpenAI reasoning models: reasoning_effort.
PROVIDER_OPTIONS: dict[AiProvider, ProviderOptions] = {
    AiProvider.ANTHROPIC: ProviderOptions(
        suggested_models=["claude-opus-5-5", "claude-sonnet-5-5", "claude-haiku-5-5", "claude-fable-5-1"],
        default_model="claude-opus-5-5",
        effort_levels=["low", "medium", "high", "xhigh", "max"],
        default_effort="high",
    ),
    AiProvider.OPENAI: ProviderOptions(
        suggested_models=["gpt-5", "gpt-5-mini"],
        default_model="gpt-5",
        effort_levels=["minimal", "low", "medium", "high"],
        default_effort="medium",
    ),
}


class AiSettingsView(BaseModel):
    """What the UI may see: never the key itself."""
    provider: AiProvider
    model: str
    effort: str
    has_stored_key: bool
    key_hint: str | None


class AnalysisTrigger(str, Enum):
    MANUAL = "manual"
    SCHEDULED = "scheduled"


class AiVerdict(str, Enum):
    COMPROMISE = "compromise"
    SUSPICIOUS = "suspicious"
    CLEAR = "clear"
    UNKNOWN = "unknown"


class AiAnalysis(BaseModel):
    provider: AiProvider
    model: str
    effort: str = ""
    question: str | None
    markdown: str
    created_at: float
    context_chars: int
    trigger: AnalysisTrigger = AnalysisTrigger.MANUAL
    verdict: AiVerdict = AiVerdict.UNKNOWN
    # Fingerprint of the security-relevant state that was analysed; lets the scheduler skip unchanged states.
    fingerprint: str = ""
