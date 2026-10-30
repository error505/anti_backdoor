import json
import urllib.error
import urllib.request

from backdoor_watch.domain.errors import ActionFailedError, ActionRefusedError
from backdoor_watch.domain.flockion import FlockionResult
from backdoor_watch.flockion.settings_store import FlockionConnection

_TIMEOUT_SECONDS = 120
_MAX_RESPONSE_CHARS = 20_000


class FlockionClient:
    def run_agent(self, connection: FlockionConnection, text: str) -> FlockionResult:
        if not connection.api_key:
            raise ActionRefusedError("Save the Flockion runtime key (starts with flk_) first")
        url = connection.run_url()
        headers = {
            "Content-Type": "application/json", "Accept": "application/json",
            connection.auth_header: f"{connection.auth_scheme} {connection.api_key}".strip(),
        }
        body = json.dumps({connection.body_field: text}).encode("utf-8")
        request = urllib.request.Request(url, data=body, headers=headers, method="POST")
        try:
            with urllib.request.urlopen(request, timeout=_TIMEOUT_SECONDS) as response:
                return self._result(url, response.status, response.read(), len(text))
        except urllib.error.HTTPError as exc:
            return self._result(url, exc.code, exc.read(), len(text))
        except (urllib.error.URLError, TimeoutError) as exc:
            raise ActionFailedError(f"Could not reach {connection.base_url}: {exc}") from exc

    @staticmethod
    def _result(url: str, status: int, payload: bytes, sent: int) -> FlockionResult:
        text = payload.decode("utf-8", errors="replace")[:_MAX_RESPONSE_CHARS]
        return FlockionResult(status_code=status, ok=200 <= status < 300, url=url, sent_chars=sent, response_text=text)
