"""Authenticode verification with caching.

Each verification costs a PowerShell round-trip, so lookups never block:
unknown paths are queued and verified in batches by a background job.
"""

import logging
import os
import threading
from collections.abc import Iterable

from backdoor_watch.domain.process import SignatureInfo
from backdoor_watch.platform.powershell import PowerShellError, run_powershell_json

logger = logging.getLogger(__name__)

_VERIFY_SCRIPT = r"""
$out = foreach ($p in ($env:BW_ARGS | ConvertFrom-Json)) {
  try {
    $s = Get-AuthenticodeSignature -LiteralPath $p -ErrorAction Stop
    [pscustomobject]@{ path = $p; status = [string]$s.Status;
      subject = $(if ($s.SignerCertificate) { $s.SignerCertificate.Subject } else { $null }) }
  } catch {
    [pscustomobject]@{ path = $p; status = 'Unreadable'; subject = $null }
  }
}
ConvertTo-Json -InputObject @($out) -Compress
"""

_UNKNOWN = SignatureInfo(status="Unknown")


class SignatureVerifier:
    def __init__(self, batch_size: int = 60) -> None:
        self._batch_size = batch_size
        self._cache: dict[str, SignatureInfo] = {}
        self._pending: set[str] = set()
        self._lock = threading.Lock()

    def lookup(self, path: str | None) -> SignatureInfo | None:
        if not path:
            return None
        with self._lock:
            cached = self._cache.get(os.path.normcase(path))
            if cached is None:
                self._pending.add(path)
        return cached

    def verify_pending(self) -> None:
        with self._lock:
            batch = list(self._pending)[: self._batch_size]
        if batch:
            self._store(batch, self._verify(batch))

    def verify_now(self, paths: Iterable[str]) -> dict[str, SignatureInfo]:
        """Synchronous verification for scans that need results immediately."""
        wanted = {p for p in paths if p}
        with self._lock:
            missing = [p for p in wanted if os.path.normcase(p) not in self._cache]
        for start in range(0, len(missing), self._batch_size):
            batch = missing[start:start + self._batch_size]
            self._store(batch, self._verify(batch))
        with self._lock:
            return {p: self._cache.get(os.path.normcase(p), _UNKNOWN) for p in wanted}

    def _store(self, batch: list[str], results: dict[str, SignatureInfo]) -> None:
        with self._lock:
            for path in batch:
                self._pending.discard(path)
                self._cache[os.path.normcase(path)] = results.get(path, _UNKNOWN)

    @staticmethod
    def _verify(paths: list[str]) -> dict[str, SignatureInfo]:
        try:
            rows = run_powershell_json(_VERIFY_SCRIPT, paths, timeout=180)
        except (PowerShellError, ValueError) as exc:
            logger.warning("signature_verification_failed", extra={"error": str(exc)})
            return {}
        return {row["path"]: SignatureInfo(status=row["status"], subject=row.get("subject"))
                for row in rows if row.get("path")}
