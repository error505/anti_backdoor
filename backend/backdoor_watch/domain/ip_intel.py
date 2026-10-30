from pydantic import BaseModel


class IpIntel(BaseModel):
    """Who owns a remote address and where it is registered. Registration data, not proof of intent."""
    ip: str
    country: str | None = None
    country_code: str | None = None
    region: str | None = None
    city: str | None = None
    org: str | None = None
    asn: str | None = None
    reverse_dns: str | None = None
    cloud_hosting: bool = False
    error: str | None = None


class IpIntelBatch(BaseModel):
    enabled: bool
    results: list[IpIntel]


class IpIntelSettingsView(BaseModel):
    enabled: bool
    provider: str
    cached_addresses: int
