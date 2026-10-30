"""Rent-by-the-hour networks. Contagious Interview servers usually sit on these, as do countless legitimate
services, so a match is context for the analyst and never a verdict."""

_HOSTING_KEYWORDS = (
    "amazon", "aws", "google", "microsoft", "azure", "cloudflare", "digitalocean", "linode", "akamai", "vultr",
    "choopa", "hetzner", "ovh", "contabo", "m247", "leaseweb", "scaleway", "oracle", "alibaba", "tencent",
    "hostinger", "namecheap", "godaddy", "ionos", "kamatera", "datacamp", "colocrossing", "quadranet",
    "psychz", "hosting", "vps", "cloud", "server", "datacenter", "data center",
)


def is_cloud_hosting(org: str | None) -> bool:
    if not org:
        return False
    lowered = org.lower()
    return any(keyword in lowered for keyword in _HOSTING_KEYWORDS)
