import openai

from backdoor_watch.ai.analyst import AiProviderError


class OpenAiAnalyst:
    def __init__(self, model: str, effort: str, api_key: str | None) -> None:
        self._model = model
        self._effort = effort
        try:
            # Without a stored key the SDK reads OPENAI_API_KEY from the environment.
            self._client = openai.OpenAI(api_key=api_key) if api_key else openai.OpenAI()
        except openai.OpenAIError as exc:
            raise AiProviderError(f"OpenAI client not configured: {exc}") from exc

    def analyze(self, system_prompt: str, user_content: str) -> str:
        try:
            response = self._client.chat.completions.create(
                model=self._model,
                reasoning_effort=self._effort,
                messages=[{"role": "system", "content": system_prompt}, {"role": "user", "content": user_content}],
            )
        except openai.AuthenticationError as exc:
            raise AiProviderError("OpenAI rejected the API key") from exc
        except openai.RateLimitError as exc:
            raise AiProviderError("OpenAI rate limit or quota reached") from exc
        except openai.BadRequestError as exc:
            # Non-reasoning models (e.g. gpt-4o) reject reasoning_effort.
            raise AiProviderError(f"OpenAI rejected the request (does '{self._model}' support reasoning "
                                  f"effort?): {exc.message}") from exc
        except openai.APIStatusError as exc:
            raise AiProviderError(f"OpenAI API error {exc.status_code}: {exc.message}") from exc
        except openai.APIConnectionError as exc:
            raise AiProviderError("Could not reach api.openai.com") from exc
        choice = response.choices[0]
        if getattr(choice.message, "refusal", None):
            raise AiProviderError(f"The model declined: {choice.message.refusal}")
        return choice.message.content or ""
