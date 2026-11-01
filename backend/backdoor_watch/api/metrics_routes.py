from fastapi import APIRouter, Depends

from backdoor_watch.api.deps import get_services
from backdoor_watch.container import AppServices
from backdoor_watch.domain.metrics import MetricsHistory
from backdoor_watch.monitoring.metrics_recorder import SAMPLE_INTERVAL_SECONDS

router = APIRouter(prefix="/api/metrics")


@router.get("")
def history(services: AppServices = Depends(get_services)) -> MetricsHistory:
    return MetricsHistory(metering=services.settings.demo or services.meter.available,
                          interval_seconds=SAMPLE_INTERVAL_SECONDS, samples=services.metrics.samples())
