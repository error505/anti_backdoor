from pydantic import BaseModel


class MetricSample(BaseModel):
    """One reading of the whole machine, taken every few seconds, for the dashboard charts."""
    t: float
    rate_out: float
    rate_in: float
    external_connections: int
    network_listeners: int
    processes: int
    critical: int
    high: int
    medium: int


class MetricsHistory(BaseModel):
    metering: bool
    interval_seconds: float
    samples: list[MetricSample]
