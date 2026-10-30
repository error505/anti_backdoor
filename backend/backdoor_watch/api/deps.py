from fastapi import Request
from pydantic import BaseModel

from backdoor_watch.container import AppServices


def get_services(request: Request) -> AppServices:
    return request.app.state.services


class ActionResult(BaseModel):
    message: str
