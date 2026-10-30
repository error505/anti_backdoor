"""Per-connection byte counters via the Windows TCP Extended Statistics API.

Windows does not expose per-process network bytes directly. EStats lets us
enable data collection on each established TCP connection and then read
DataBytesOut / DataBytesIn. Requires administrator rights. Counting starts
when collection is enabled, so bytes sent before the monitor saw a
connection are not included.
"""

import ctypes
import socket
import struct
from ctypes import wintypes

from backdoor_watch.domain.addresses import strip_scope
from backdoor_watch.domain.network import ConnectionKey

_TCP_CONNECTION_ESTATS_DATA = 1
_MIB_TCP_STATE_ESTAB = 5
_ERROR_ACCESS_DENIED = 5


class _MibTcpRow(ctypes.Structure):
    _fields_ = [("state", wintypes.DWORD), ("local_addr", wintypes.DWORD),
                ("local_port", wintypes.DWORD), ("remote_addr", wintypes.DWORD),
                ("remote_port", wintypes.DWORD)]


class _MibTcp6Row(ctypes.Structure):
    _fields_ = [("state", wintypes.DWORD), ("local_addr", ctypes.c_ubyte * 16),
                ("local_scope_id", wintypes.DWORD), ("local_port", wintypes.DWORD),
                ("remote_addr", ctypes.c_ubyte * 16), ("remote_scope_id", wintypes.DWORD),
                ("remote_port", wintypes.DWORD)]


class _DataRw(ctypes.Structure):
    _fields_ = [("enable_collection", ctypes.c_ubyte)]


class _DataRod(ctypes.Structure):
    _fields_ = [("data_bytes_out", ctypes.c_uint64), ("data_segs_out", ctypes.c_uint64),
                ("data_bytes_in", ctypes.c_uint64), ("data_segs_in", ctypes.c_uint64),
                ("segs_out", ctypes.c_uint64), ("segs_in", ctypes.c_uint64),
                ("soft_errors", ctypes.c_ulong), ("soft_error_reason", ctypes.c_ulong),
                ("snd_una", ctypes.c_ulong), ("snd_nxt", ctypes.c_ulong),
                ("snd_max", ctypes.c_ulong), ("thru_bytes_acked", ctypes.c_uint64),
                ("rcv_nxt", ctypes.c_ulong), ("thru_bytes_received", ctypes.c_uint64)]


def _bind(name: str):
    function = getattr(ctypes.WinDLL("iphlpapi"), name)
    function.restype = ctypes.c_ulong
    return function


_set_v4, _get_v4 = _bind("SetPerTcpConnectionEStats"), _bind("GetPerTcpConnectionEStats")
_set_v6, _get_v6 = _bind("SetPerTcp6ConnectionEStats"), _bind("GetPerTcp6ConnectionEStats")


def _ipv4_row(local_ip: str, local_port: int, remote_ip: str, remote_port: int) -> _MibTcpRow:
    def addr(ip: str) -> int:
        return struct.unpack("<I", socket.inet_aton(ip))[0]
    return _MibTcpRow(_MIB_TCP_STATE_ESTAB, addr(local_ip), socket.htons(local_port),
                      addr(remote_ip), socket.htons(remote_port))


def _ipv6_row(local_ip: str, local_port: int, remote_ip: str, remote_port: int) -> _MibTcp6Row:
    def addr(ip: str):
        return (ctypes.c_ubyte * 16).from_buffer_copy(socket.inet_pton(socket.AF_INET6, strip_scope(ip)))
    return _MibTcp6Row(_MIB_TCP_STATE_ESTAB, addr(local_ip), 0, socket.htons(local_port),
                       addr(remote_ip), 0, socket.htons(remote_port))


class TcpTrafficMeter:
    def __init__(self) -> None:
        self._enabled: set[ConnectionKey] = set()
        self.available = True

    def read(self, key: ConnectionKey, is_ipv6: bool) -> tuple[int, int] | None:
        """Returns (bytes_out, bytes_in) or None when unavailable."""
        _, local_ip, local_port, remote_ip, remote_port = key
        if not self.available or remote_ip is None or remote_port is None:
            return None
        build_row = _ipv6_row if is_ipv6 else _ipv4_row
        set_fn, get_fn = (_set_v6, _get_v6) if is_ipv6 else (_set_v4, _get_v4)
        try:
            row = build_row(local_ip, local_port, remote_ip, remote_port)
        except OSError:
            return None
        if key not in self._enabled and not self._enable(set_fn, row, key):
            return None
        rod = _DataRod()
        result = get_fn(ctypes.byref(row), _TCP_CONNECTION_ESTATS_DATA, None, 0, 0, None, 0, 0,
                        ctypes.byref(rod), 0, ctypes.sizeof(rod))
        return (rod.data_bytes_out, rod.data_bytes_in) if result == 0 else None

    def forget_except(self, active: set[ConnectionKey]) -> None:
        self._enabled &= active

    def _enable(self, set_fn, row, key: ConnectionKey) -> bool:
        rw = _DataRw(1)
        result = set_fn(ctypes.byref(row), _TCP_CONNECTION_ESTATS_DATA, ctypes.byref(rw), 0,
                        ctypes.sizeof(rw), 0)
        if result == _ERROR_ACCESS_DENIED:
            self.available = False
        if result == 0:
            self._enabled.add(key)
        return result == 0
