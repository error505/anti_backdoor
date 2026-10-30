import json
import time
import urllib.error
import urllib.request
import uuid

from websockets.exceptions import ConnectionClosed, InvalidHandshake, InvalidURI
from websockets.sync.client import connect

from backdoor_watch.domain.errors import ActionFailedError
from backdoor_watch.domain.flockion import FlockionCheck, FlockionResult
from backdoor_watch.flockion.settings_store import FlockionConnection

_HTTP_TIMEOUT = 15
_RUN_DEADLINE_SECONDS = 300
_MAX_FRAME_BYTES = 1_000_000
# Hard spend cap for one analysis, enforced by Flockion. The extension uses 5; a snapshot needs far less.
BUDGET_CAP_USD = 2
_DENIED = "Backdoor Watch is a read-only monitor, not an editor workspace. Answer from the snapshot text only."


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """A redirect would forward the Bearer key to another host, so redirects are errors."""

    def redirect_request(self, *args, **kwargs):  # noqa: D401
        return None


class FlockionClient:
    def check(self, connection: FlockionConnection) -> FlockionCheck:
        """Validates endpoint and key without starting a task or sending any system data."""
        endpoint, key = connection.parsed(), connection.require_key()
        url = endpoint.operation_url("editor-models")
        request = urllib.request.Request(url, headers={"Authorization": f"Bearer {key}", "Accept": "application/json"})
        try:
            with urllib.request.build_opener(_NoRedirect).open(request, timeout=_HTTP_TIMEOUT) as response:
                body = self._json(response.read(), response.headers.get("Content-Type", ""), url)
        except urllib.error.HTTPError as exc:
            return FlockionCheck(ok=False, asset_name=None, model_count=0, detail=self._http_error(exc))
        except (urllib.error.URLError, TimeoutError) as exc:
            raise ActionFailedError(f"Could not reach {endpoint.api_access_url}: {exc}") from exc
        items = body.get("items")
        if not isinstance(items, list):
            return FlockionCheck(ok=False, asset_name=None, model_count=0,
                                 detail="The server did not return a Flockion editor model catalog. Check the API URL.")
        name = body.get("assetName")
        return FlockionCheck(ok=True, asset_name=name.strip()[:120] if isinstance(name, str) and name.strip() else None,
                             model_count=len(items), detail="Connected: the key is valid for this agent")

    def run(self, connection: FlockionConnection, text: str) -> FlockionResult:
        endpoint, key = connection.parsed(), connection.require_key()
        denied = 0
        try:
            # The websockets sync client never follows redirects, so the key cannot be forwarded to another host.
            with connect(endpoint.websocket_url(), open_timeout=_HTTP_TIMEOUT, max_size=_MAX_FRAME_BYTES) as socket:
                socket.send(json.dumps({"kind": "start", "token": key, "sessionId": str(uuid.uuid4()),
                                        "requestId": str(uuid.uuid4()), "message": text, "mode": "ask",
                                        "permissionMode": "review", "budgetCapUsd": BUDGET_CAP_USD}))
                deadline = time.monotonic() + _RUN_DEADLINE_SECONDS
                while True:
                    frame = self._frame(socket.recv(timeout=max(deadline - time.monotonic(), 0.1)))
                    kind = frame.get("kind")
                    if kind == "error":
                        raise ActionFailedError(str(frame.get("message") or "Flockion rejected the request")[:350])
                    if kind in ("approval_required", "execute_tool"):
                        denied += 1
                        socket.send(json.dumps(self._refusal(frame)))
                    elif kind in ("done", "cancelled"):
                        return self._result(frame, len(text), denied)
        except TimeoutError as exc:
            raise ActionFailedError("Flockion did not finish within 5 minutes; the task may still be running there") from exc
        except InvalidURI as exc:
            raise ActionFailedError(f"Invalid Flockion address: {exc}") from exc
        except InvalidHandshake as exc:
            raise ActionFailedError(f"Could not open the Flockion editor connection ({exc}). Check the API URL; "
                                    "https://flockion.com is the website, the API is api.flockion.com/api/v1") from exc
        except ConnectionClosed as exc:
            raise ActionFailedError("Connection to Flockion closed before the task finished") from exc
        except OSError as exc:
            raise ActionFailedError(f"Could not reach Flockion: {exc}") from exc

    @staticmethod
    def _frame(raw: str | bytes) -> dict:
        frame = json.loads(raw)
        if not isinstance(frame, dict):
            raise ActionFailedError("Invalid Flockion message")
        return frame

    @staticmethod
    def _refusal(frame: dict) -> dict:
        action_id = frame.get("actionId")
        if frame.get("kind") == "approval_required":
            return {"kind": "approval", "actionId": action_id, "approved": False}
        return {"kind": "tool_result", "actionId": action_id, "result": {"ok": False, "error": _DENIED}}

    @staticmethod
    def _result(frame: dict, sent: int, denied: int) -> FlockionResult:
        result = frame.get("result") if isinstance(frame.get("result"), dict) else {}
        status = str(result.get("status") or frame.get("kind"))
        output = result.get("output") if isinstance(result.get("output"), str) else result.get("error")
        spend = result.get("spend") if isinstance(result.get("spend"), dict) else {}
        cost, tokens = spend.get("costUsd"), spend.get("totalTokens")
        return FlockionResult(ok=status == "succeeded", status=status, output=str(output or f"Request status: {status}"),
                              sent_chars=sent, cost_usd=cost if isinstance(cost, (int, float)) else None,
                              total_tokens=int(tokens) if isinstance(tokens, (int, float)) else None,
                              denied_tool_requests=denied)

    @staticmethod
    def _json(payload: bytes, content_type: str, url: str) -> dict:
        if "html" in content_type.lower():
            raise ActionFailedError(f"{url} returned a web page, not the API. https://flockion.com is the website; "
                                    "use https://api.flockion.com/api/v1/…")
        try:
            data = json.loads(payload)
        except ValueError as exc:
            raise ActionFailedError("Flockion returned a response that is not JSON") from exc
        return data if isinstance(data, dict) else {}

    @staticmethod
    def _http_error(exc: urllib.error.HTTPError) -> str:
        try:
            detail = json.loads(exc.read()).get("detail")
        except (ValueError, AttributeError):
            detail = None
        return f"HTTP {exc.code}: {str(detail)[:300] if detail else exc.reason}"
