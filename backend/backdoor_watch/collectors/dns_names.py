"""Maps IP addresses back to the hostnames that resolved to them.

Sources: the Windows DNS client cache (polled) and live DNS answers seen by
the packet sniffer. This is how "203.0.113.5" becomes "evil-cdn.vercel.app".
"""

import logging
import threading

from backdoor_watch.domain.addresses import strip_scope
from backdoor_watch.platform.powershell import PowerShellError, run_powershell_json

logger = logging.getLogger(__name__)

_DNS_CACHE_SCRIPT = r"""
$out = Get-DnsClientCache -ErrorAction SilentlyContinue |
  Where-Object { $_.Type -eq 1 -or $_.Type -eq 28 } |
  Select-Object @{n='name';e={$_.Entry}}, @{n='ip';e={$_.Data}}
ConvertTo-Json -InputObject @($out) -Compress
"""


class DnsNameResolver:
    def __init__(self) -> None:
        self._names: dict[str, str] = {}
        self._lock = threading.Lock()

    def record(self, ip: str, hostname: str) -> None:
        with self._lock:
            self._names[strip_scope(ip)] = hostname.rstrip(".")

    def name_for(self, ip: str | None) -> str | None:
        if not ip:
            return None
        with self._lock:
            return self._names.get(strip_scope(ip))

    def refresh_from_system_cache(self) -> None:
        try:
            rows = run_powershell_json(_DNS_CACHE_SCRIPT, timeout=30)
        except (PowerShellError, ValueError) as exc:
            logger.warning("dns_cache_refresh_failed", extra={"error": str(exc)})
            return
        for row in rows:
            if row.get("ip") and row.get("name"):
                self.record(row["ip"], row["name"])
