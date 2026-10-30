from typing import Annotated

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel

from backdoor_watch.api.deps import get_services
from backdoor_watch.container import AppServices
from backdoor_watch.domain.ip_intel import IpIntelBatch, IpIntelSettingsView
from backdoor_watch.ip_intel.ip_intel_service import MAX_ADDRESSES_PER_CALL

router = APIRouter(prefix="/api/intel")


class IpIntelSettingsRequest(BaseModel):
    enabled: bool


@router.get("/settings")
def get_settings(services: AppServices = Depends(get_services)) -> IpIntelSettingsView:
    return services.ip_intel.view()


@router.post("/settings")
def save_settings(body: IpIntelSettingsRequest, services: AppServices = Depends(get_services)) -> IpIntelSettingsView:
    services.ip_intel.set_enabled(body.enabled)
    return services.ip_intel.view()


@router.get("/ips")
def look_up(ip: Annotated[list[str], Query(max_length=MAX_ADDRESSES_PER_CALL)],
            services: AppServices = Depends(get_services)) -> IpIntelBatch:
    return IpIntelBatch(enabled=services.ip_intel.enabled, results=services.ip_intel.lookup(ip))
