import os
import socket

from backdoor_watch.reporting.redaction import Redactor


def test_masks_token_arguments_and_known_key_formats():
    redactor = Redactor(anonymize_identity=False)
    text = redactor.text("node app.js --token abc123def456 API_KEY=supersecret sk-ant-api03-AAAAAAAAAAAAAAAAAAAA")
    assert "abc123def456" not in text
    assert "supersecret" not in text
    assert "sk-ant-api03" not in text
    assert "node app.js" in text


def test_masks_bearer_headers():
    text = Redactor(anonymize_identity=False).text("curl -H 'Authorization: Bearer eyJhbGciOiJIUzI1NiJ9xxxxxx'")
    assert "eyJhbGciOiJIUzI1NiJ9" not in text


def test_shortens_long_encoded_payloads_but_keeps_evidence():
    blob = "A" * 300
    text = Redactor(anonymize_identity=False).text(f"powershell -enc {blob}")
    assert "[300 chars]" in text and len(text) < 120


def test_anonymizes_user_and_host_names():
    user = os.environ["USERNAME"]
    text = Redactor().text(rf"C:\Users\{user}\.n2\pay on {socket.gethostname()}")
    assert user.lower() not in text.lower()
    assert r"\.n2\pay" in text


def test_redacts_nested_structures():
    data = {"processes": [{"cmdline": "app --password hunter2"}], "count": 3}
    redacted = Redactor(anonymize_identity=False).value(data)
    assert "hunter2" not in redacted["processes"][0]["cmdline"]
    assert redacted["count"] == 3
