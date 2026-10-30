import ipaddress

ALL_INTERFACES = frozenset({"0.0.0.0", "::"})


def strip_scope(ip: str) -> str:
    return ip.split("%", 1)[0]


def is_public_address(ip: str | None) -> bool:
    if not ip:
        return False
    try:
        return ipaddress.ip_address(strip_scope(ip)).is_global
    except ValueError:
        return False


def is_loopback_address(ip: str) -> bool:
    try:
        return ipaddress.ip_address(strip_scope(ip)).is_loopback
    except ValueError:
        return False
