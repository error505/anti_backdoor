import anthropic

from backdoor_watch.ai.analyst import AiProviderError

# Security triage text can trip the cyber safety classifier; server-side fallbacks let
# Anthropic re-run a declined request on a suitable model instead of failing outright.
_FALLBACK_BETA = "server-side-fallback-2026-07-01"
_FALLBACK_MODELS = frozenset({"claude-fable-5-1", "claude-opus-5-5", "claude-opus-5", "claude-sonnet-5-5"})
_MAX_TOKENS = 32000


class AnthropicAnalyst:
    def __init__(self, model: str, effort: str, api_key: str | None) -> None:
        self._model = model
        self._effort = effort
        try:
            # Without a stored key the SDK resolves ANTHROPIC_API_KEY or an `ant auth login` profile.
            self._client = anthropic.Anthropic(api_key=api_key) if api_key else anthropic.Anthropic()
        except anthropic.AnthropicError as exc:
            raise AiProviderError(f"Anthropic client not configured: {exc}") from exc

    def analyze(self, system_prompt: str, user_content: str) -> str:
        fallback = ({"betas": [_FALLBACK_BETA], "fallbacks": "default"} if self._model in _FALLBACK_MODELS else {})
        try:
            with self._client.beta.messages.stream(
                model=self._model, max_tokens=_MAX_TOKENS, system=system_prompt,
                messages=[{"role": "user", "content": user_content}],
                output_config={"effort": self._effort}, **fallback,
            ) as stream:
                message = stream.get_final_message()
        except anthropic.AuthenticationError as exc:
            raise AiProviderError("Anthropic rejected the API key") from exc
        except anthropic.RateLimitError as exc:
            raise AiProviderError("Anthropic rate limit reached; try again in a minute") from exc
        except anthropic.APIStatusError as exc:
            raise AiProviderError(f"Anthropic API error {exc.status_code}: {exc.message}") from exc
        except anthropic.APIConnectionError as exc:
            raise AiProviderError("Could not reach api.anthropic.com") from exc
        if message.stop_reason == "refusal":
            details = getattr(message, "stop_details", None)
            raise AiProviderError(f"The model declined this request ({getattr(details, 'category', None) or 'policy'})")
        text = "".join(block.text for block in message.content if block.type == "text")
        if message.stop_reason == "max_tokens":
            text += "\n\n_(Analysis truncated at the output limit.)_"
        return text
