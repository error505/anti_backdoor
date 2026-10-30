"""Pure parsers for the parts of outbound traffic that reveal *what* is sent.

Most traffic is TLS-encrypted, so the content itself is not readable. What
remains visible: the server name in the TLS ClientHello (SNI), DNS queries,
and anything sent in plaintext (BeaverTail-style loaders often use plain
HTTP to a raw IP).
"""

_HTTP_METHODS = (b"GET ", b"POST ", b"PUT ", b"PATCH ", b"DELETE ", b"HEAD ", b"OPTIONS ", b"CONNECT ")
_TLS_HANDSHAKE = 0x16
_TLS_CLIENT_HELLO = 0x01
_SNI_EXTENSION = 0x0000


def is_tls_record(payload: bytes) -> bool:
    return len(payload) >= 3 and 0x14 <= payload[0] <= 0x17 and payload[1] == 0x03


def _skip_vector(payload: bytes, offset: int, length_bytes: int) -> int:
    length = int.from_bytes(payload[offset:offset + length_bytes], "big")
    return offset + length_bytes + length


def _read_sni_extension(data: bytes) -> str | None:
    # server_name_list length (2), name_type (1), host_name length (2), host_name
    if len(data) < 5 or data[2] != 0:
        return None
    length = int.from_bytes(data[3:5], "big")
    return data[5:5 + length].decode("ascii", errors="replace") or None


def parse_tls_sni(payload: bytes) -> str | None:
    if len(payload) < 43 or payload[0] != _TLS_HANDSHAKE or payload[5] != _TLS_CLIENT_HELLO:
        return None
    try:
        offset = 5 + 4 + 2 + 32                     # record hdr, handshake hdr, version, random
        offset = _skip_vector(payload, offset, 1)   # session id
        offset = _skip_vector(payload, offset, 2)   # cipher suites
        offset = _skip_vector(payload, offset, 1)   # compression methods
        end = _skip_vector(payload, offset, 2)
        offset += 2
        while offset + 4 <= min(end, len(payload)):
            ext_type = int.from_bytes(payload[offset:offset + 2], "big")
            ext_len = int.from_bytes(payload[offset + 2:offset + 4], "big")
            if ext_type == _SNI_EXTENSION:
                return _read_sni_extension(payload[offset + 4:offset + 4 + ext_len])
            offset += 4 + ext_len
    except IndexError:
        return None
    return None


def printable_preview(payload: bytes, limit: int = 512) -> str:
    chunk = payload[:limit]
    text = "".join(chr(b) if 32 <= b < 127 or b in (9, 10, 13) else "·" for b in chunk)
    return text + ("…" if len(payload) > limit else "")


def parse_http_request(payload: bytes) -> tuple[str, str] | None:
    """Returns (request line, preview of headers + body) for plaintext HTTP requests."""
    if not payload.startswith(_HTTP_METHODS):
        return None
    request_line = payload.split(b"\r\n", 1)[0].decode("latin-1")
    return request_line, printable_preview(payload, limit=2048)
