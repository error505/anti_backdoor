from typing import Protocol

from backdoor_watch.domain.errors import BackdoorWatchError


class AiProviderError(BackdoorWatchError):
    """The AI provider could not produce an analysis (bad key, quota, refusal, network)."""


class SecurityAnalyst(Protocol):
    def analyze(self, system_prompt: str, user_content: str) -> str: ...
