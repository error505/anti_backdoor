import socket
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import TimeoutError as FutureTimeout

_TIMEOUT_SECONDS = 3
_pool = ThreadPoolExecutor(max_workers=4, thread_name_prefix="rdns")


def reverse_dns(ip: str) -> str | None:
    """PTR name via the system resolver; gethostbyaddr has no timeout, so it runs in a worker."""
    future = _pool.submit(socket.gethostbyaddr, ip)
    try:
        return future.result(timeout=_TIMEOUT_SECONDS)[0]
    except (OSError, FutureTimeout):
        return None
