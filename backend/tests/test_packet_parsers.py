from backdoor_watch.capture.packet_parsers import is_tls_record, parse_http_request, parse_tls_sni


def _client_hello(server_name: str) -> bytes:
    name = server_name.encode()
    sni_body = (len(name) + 3).to_bytes(2, "big") + b"\x00" + len(name).to_bytes(2, "big") + name
    extension = b"\x00\x00" + len(sni_body).to_bytes(2, "big") + sni_body
    extensions = len(extension).to_bytes(2, "big") + extension
    body = (b"\x03\x03" + b"\x00" * 32 + b"\x00"            # version, random, empty session id
            + b"\x00\x02\x13\x01" + b"\x01\x00" + extensions)  # one cipher suite, null compression
    handshake = b"\x01" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x01" + len(handshake).to_bytes(2, "big") + handshake


def test_extracts_sni_from_client_hello():
    assert parse_tls_sni(_client_hello("c2.example.vercel.app")) == "c2.example.vercel.app"


def test_non_tls_payload_has_no_sni():
    assert parse_tls_sni(b"GET / HTTP/1.1\r\n\r\n" + b"x" * 60) is None


def test_truncated_client_hello_does_not_crash():
    assert parse_tls_sni(_client_hello("example.com")[:50]) is None


def test_detects_plaintext_http_request():
    request_line, preview = parse_http_request(b"POST /uploads HTTP/1.1\r\nHost: 1.2.3.4:1224\r\n\r\nsecret")
    assert request_line == "POST /uploads HTTP/1.1"
    assert "secret" in preview


def test_tls_application_data_is_recognized_as_encrypted():
    assert is_tls_record(b"\x17\x03\x03\x00\x10")
