"""Windows DPAPI: encrypts secrets so only this Windows user account can decrypt them."""

import ctypes
from ctypes import wintypes

_CRYPTPROTECT_UI_FORBIDDEN = 0x1


class _DataBlob(ctypes.Structure):
    _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_char))]


def _blob(data: bytes) -> tuple[_DataBlob, ctypes.Array]:
    buffer = ctypes.create_string_buffer(data, len(data))
    return _DataBlob(len(data), ctypes.cast(buffer, ctypes.POINTER(ctypes.c_char))), buffer


def _call(function, data: bytes) -> bytes:
    source, _keepalive = _blob(data)
    output = _DataBlob()
    if not function(ctypes.byref(source), None, None, None, None, _CRYPTPROTECT_UI_FORBIDDEN, ctypes.byref(output)):
        raise OSError(ctypes.get_last_error(), "DPAPI call failed")
    try:
        return ctypes.string_at(output.pbData, output.cbData)
    finally:
        ctypes.windll.kernel32.LocalFree(output.pbData)


def protect(data: bytes) -> bytes:
    return _call(ctypes.windll.crypt32.CryptProtectData, data)


def unprotect(data: bytes) -> bytes:
    return _call(ctypes.windll.crypt32.CryptUnprotectData, data)
