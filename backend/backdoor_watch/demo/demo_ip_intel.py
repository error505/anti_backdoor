"""Fictional registration data for the documentation-range addresses used by demo mode (no network access)."""

from backdoor_watch.domain.ip_intel import IpIntel
from backdoor_watch.ip_intel.hosting_providers import is_cloud_hosting

_RECORDS = {
    "203.0.113.45": ("Netherlands", "NL", "Noord-Holland", "Amsterdam", "Example VPS Hosting B.V.", "AS64500"),
    "198.51.100.77": ("Germany", "DE", "Hesse", "Frankfurt", "Sample Cloud Servers GmbH", "AS64501"),
}
_GENERIC = ("United States", "US", "California", "San Francisco", "Example Edge Network Inc.", "AS64502")


class DemoIpProvider:
    name = "demo (fictional)"

    def lookup(self, ip: str) -> IpIntel:
        country, code, region, city, org, asn = _RECORDS.get(ip, _GENERIC)
        return IpIntel(ip=ip, country=country, country_code=code, region=region, city=city, org=org, asn=asn,
                       cloud_hosting=is_cloud_hosting(org))
