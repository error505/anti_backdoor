"""Looks up IP registration data over HTTPS. Only the address leaves the machine."""

import json
import urllib.error
import urllib.request

from backdoor_watch.domain.errors import ActionFailedError
from backdoor_watch.domain.ip_intel import IpIntel
from backdoor_watch.ip_intel.hosting_providers import is_cloud_hosting

_FIELDS = "ip,success,message,country,country_code,region,city,connection"
_TIMEOUT_SECONDS = 8


class IpWhoIsProvider:
    """ipwho.is: free, no key, HTTPS, about 10,000 lookups a month."""
    name = "ipwho.is"

    def __init__(self, base_url: str = "https://ipwho.is") -> None:
        self._base_url = base_url.rstrip("/")

    def lookup(self, ip: str) -> IpIntel:
        request = urllib.request.Request(f"{self._base_url}/{ip}?fields={_FIELDS}",
                                         headers={"User-Agent": "FlockionBackdoorWatch"})
        try:
            with urllib.request.urlopen(request, timeout=_TIMEOUT_SECONDS) as response:
                data = json.loads(response.read(65_536))
        except (urllib.error.URLError, TimeoutError, ValueError) as exc:
            raise ActionFailedError(f"IP lookup failed: {exc}") from exc
        if not data.get("success"):
            raise ActionFailedError(f"IP lookup refused: {data.get('message', 'unknown reason')}")
        return _to_intel(ip, data)


def _to_intel(ip: str, data: dict) -> IpIntel:
    connection = data.get("connection") or {}
    org = connection.get("org") or connection.get("isp")
    asn = connection.get("asn")
    return IpIntel(ip=ip, country=data.get("country"), country_code=data.get("country_code"),
                   region=data.get("region"), city=data.get("city"), org=org,
                   asn=f"AS{asn}" if asn else None, cloud_hosting=is_cloud_hosting(org))
