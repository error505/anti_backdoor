from fastapi import APIRouter, Depends
from pydantic import BaseModel

from backdoor_watch.api.deps import ActionResult, get_services
from backdoor_watch.container import AppServices
from backdoor_watch.domain.process import ProcessInfo
from backdoor_watch.services.process_queries import ProcessDetail

router = APIRouter(prefix="/api/processes")


class KillRequest(BaseModel):
    include_children: bool = True


@router.get("")
def list_processes(services: AppServices = Depends(get_services)) -> list[ProcessInfo]:
    return list(services.state.current.processes.values())


@router.get("/{pid}")
def process_detail(pid: int, services: AppServices = Depends(get_services)) -> ProcessDetail:
    return services.process_queries.detail(pid)


@router.post("/{pid}/kill")
def kill_process(pid: int, body: KillRequest, services: AppServices = Depends(get_services)) -> ActionResult:
    return ActionResult(message=services.response.kill_process(pid, body.include_children))


@router.post("/{pid}/suspend")
def suspend_process(pid: int, services: AppServices = Depends(get_services)) -> ActionResult:
    return ActionResult(message=services.response.suspend_process(pid))


@router.post("/{pid}/resume")
def resume_process(pid: int, services: AppServices = Depends(get_services)) -> ActionResult:
    return ActionResult(message=services.response.resume_process(pid))


@router.post("/{pid}/quarantine")
def quarantine_executable(pid: int, services: AppServices = Depends(get_services)) -> ActionResult:
    return ActionResult(message=services.response.quarantine_process_executable(pid))


@router.post("/{pid}/block")
def block_network(pid: int, services: AppServices = Depends(get_services)) -> ActionResult:
    return ActionResult(message=services.response.block_process_program(pid))
