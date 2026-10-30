"""Sends a rendered report to cloud storage or a webhook.

Works with pre-signed upload URLs (AWS S3 presigned PUT, Azure Blob SAS URL,
Google Cloud Storage signed URL) and with plain HTTPS webhooks (POST). No cloud
credentials are stored here; the URL itself carries the permission.
"""

import urllib.error
import urllib.request
from typing import Literal
from urllib.parse import urlparse

from backdoor_watch.domain.errors import ActionFailedError, ActionRefusedError

UploadMethod = Literal["PUT", "POST"]
_TIMEOUT_SECONDS = 60


def _headers_for(host: str, content_type: str) -> dict[str, str]:
    headers = {"Content-Type": content_type}
    if host.endswith(".blob.core.windows.net"):
        headers["x-ms-blob-type"] = "BlockBlob"
    return headers


class ReportUploader:
    def upload(self, url: str, method: UploadMethod, body: bytes, content_type: str) -> int:
        parsed = urlparse(url)
        if parsed.scheme != "https" or not parsed.hostname:
            raise ActionRefusedError("Only https:// upload URLs are allowed")
        request = urllib.request.Request(url, data=body, method=method,
                                         headers=_headers_for(parsed.hostname, content_type))
        try:
            with urllib.request.urlopen(request, timeout=_TIMEOUT_SECONDS) as response:
                return response.status
        except urllib.error.HTTPError as exc:
            raise ActionFailedError(f"Upload rejected: HTTP {exc.code} {exc.reason}") from exc
        except (urllib.error.URLError, TimeoutError) as exc:
            raise ActionFailedError(f"Upload failed: {exc}") from exc


def host_of(url: str) -> str:
    """For the audit log: the destination host, never the signed query string."""
    return urlparse(url).hostname or "?"
