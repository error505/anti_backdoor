from fastapi import APIRouter, Depends
from pydantic import BaseModel

from backdoor_watch.api.deps import ActionResult, get_services
from backdoor_watch.container import AppServices
from backdoor_watch.domain.network import Connection, ProcessTraffic, RemoteTraffic
from backdoor_watch.domain.security_tools import FirewallRule

router = APIRouter(prefix="/api")


class TrafficSummary(BaseModel):
    metering_available: bool
    by_process: list[ProcessTraffic]
    by_remote: list[RemoteTraffic]


class BlockIpRequest(BaseModel):
    ip: str


class BlockProgramRequest(BaseModel):
    path: str


class RemoveRuleRequest(BaseModel):
    id: str


@router.get("/connections")
def list_connections(services: AppServices = Depends(get_services)) -> list[Connection]:
    return services.state.current.connections


@router.get("/traffic")
def traffic_summary(services: AppServices = Depends(get_services)) -> TrafficSummary:
    return TrafficSummary(metering_available=services.settings.demo or services.meter.available,
                          by_process=services.ledger.by_process(), by_remote=services.ledger.by_remote())


@router.get("/firewall/rules")
def firewall_rules(services: AppServices = Depends(get_services)) -> list[FirewallRule]:
    return services.firewall.list_rules()


@router.post("/firewall/block-ip")
def block_ip(body: BlockIpRequest, services: AppServices = Depends(get_services)) -> ActionResult:
    return ActionResult(message=services.response.block_ip(body.ip))


@router.post("/firewall/block-program")
def block_program(body: BlockProgramRequest, services: AppServices = Depends(get_services)) -> ActionResult:
    return ActionResult(message=services.response.block_program(body.path))


@router.post("/firewall/rules/remove")
def remove_rule(body: RemoveRuleRequest, services: AppServices = Depends(get_services)) -> ActionResult:
    return ActionResult(message=services.response.remove_firewall_rule(body.id))
