"""Strict key parsing and clean failures at untrusted input boundaries."""
import http.client
import io
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from qrsig import cli, keys

ROOT = Path(__file__).resolve().parents[1]


@pytest.mark.parametrize("text", [
    "AA==", "AA=", "AA===", "!!!!AAAA", "AA\nA", "AA A", "+AAA", "/AAA", "AB",
])
def test_base64url_rejects_noncanonical_encoding(text):
    with pytest.raises(ValueError):
        keys.b64url_decode(text)


@pytest.mark.parametrize("raw", [b"", b"\x00", b"\xff\xff", bytes(range(32))])
def test_base64url_accepts_canonical_encoding(raw):
    assert keys.b64url_decode(keys.b64url(raw)) == raw


@pytest.mark.parametrize("constant", ["NaN", "Infinity", "-Infinity"])
@pytest.mark.parametrize("nested", [False, True])
def test_document_rejects_non_json_constants_in_unknown_members(constant, nested):
    entry: dict[str, object] = {"key": keys.b64url(bytes(range(32)))}
    document: dict[str, object] = {"qrsig": 1, "keys": [entry]}
    target = entry if nested else document
    target["extra"] = float(constant)
    with pytest.raises(ValueError, match="JSON constant"):
        keys.parse_document(json.dumps(document).encode())


def test_document_allows_constant_names_as_ordinary_strings():
    document = {"qrsig": 1, "keys": [], "extra": ["NaN", "Infinity", "-Infinity"]}
    assert keys.parse_document(json.dumps(document).encode()) == []


@pytest.mark.parametrize("version", [True, 1.0])
def test_document_requires_integer_version(version):
    with pytest.raises(ValueError, match="qrsig 1"):
        keys.parse_document(json.dumps({"qrsig": version, "keys": []}).encode())


@pytest.mark.parametrize("suffix", ["=", "!!!!", "\n", " "])
def test_document_rejects_noncanonical_public_key(suffix):
    public = keys.b64url(bytes(range(32))) + suffix
    with pytest.raises(ValueError):
        keys.parse_document(json.dumps({"qrsig": 1, "keys": [{"key": public}]}).encode())


@pytest.mark.parametrize("body", [
    b"not json", b"\xff", b"{}", b"[]", b"null",
    b'{"private_key": null}', b'{"private_key": 123}',
    b'{"private_key": []}', b'{"private_key": "not-a-key"}',
])
def test_cli_bad_key_file_returns_usage_error(tmp_path, capsys, body):
    key = tmp_path / "key.json"
    key.write_bytes(body)
    output = tmp_path / "code.png"
    assert cli.main(["sign", "x", "--domain", "pay.example.com", "--key", str(key),
                     "-o", str(output)]) == 2
    assert capsys.readouterr().err.startswith("error:")
    assert not output.exists()


@pytest.mark.parametrize("pin", ["missing-separator", "pay.example.com=", "={doc}",
                                "localhost={doc}", "Example.com={doc}", "pay.example.com=missing"])
def test_cli_bad_pin_returns_usage_error(tmp_path, capsys, pin):
    doc = tmp_path / "keys.json"
    doc.write_text('{"qrsig": 1, "keys": []}')
    assert cli.main(["verify", str(ROOT / "examples/unsigned-bitcoin.png"),
                     "--pin", pin.format(doc=doc)]) == 2
    assert capsys.readouterr().err.startswith("error:")


def test_cli_malformed_pin_document_returns_usage_error(tmp_path, capsys):
    doc = tmp_path / "keys.json"
    doc.write_text("not json")
    assert cli.main(["verify", str(ROOT / "examples/unsigned-bitcoin.png"),
                     "--pin", f"pay.example.com={doc}"]) == 2
    assert capsys.readouterr().err.startswith("error:")


@pytest.mark.parametrize("command", ["sign", "keygen"])
def test_cli_file_errors_return_usage_error(tmp_path, capsys, command):
    existing = tmp_path / "existing"
    if command == "sign":
        argv = ["sign", "x", "--domain", "pay.example.com", "--key", str(tmp_path / "missing"),
                "-o", str(tmp_path / "out.png")]
    else:
        existing.write_text("keep me")
        argv = ["keygen", "-o", str(existing)]
    assert cli.main(argv) == 2
    assert capsys.readouterr().err.startswith("error:")
    if command == "keygen":
        assert existing.read_text() == "keep me"


@pytest.mark.parametrize("wire", [
    b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\na\r\n{",
    b"NOT AN HTTP RESPONSE\r\n\r\n",
    b'HTTP/1.1 200 OK\r\nContent-Length: 200\r\n\r\n{"qrsig":1,"keys":[]}',
])
def test_http_protocol_failures_mean_keys_unavailable(monkeypatch, wire):
    # Exercise the real HTTP parser without a network or TLS dependency.
    def open_response(request, timeout):
        response = http.client.HTTPResponse(SimpleNamespace(makefile=lambda mode: io.BytesIO(wire)))
        response.begin()
        return response

    monkeypatch.setattr(keys.urllib.request, "build_opener",
                        lambda *handlers: SimpleNamespace(open=open_response))
    with pytest.raises(keys.KeysUnavailable):
        keys.fetch("pay.example.com")


@pytest.mark.parametrize("headers,body", [
    (b"Content-Length: 21\r\n", b'{"qrsig":1,"keys":[]}'),
    (b"", b'{"qrsig":1,"keys":[]}'),
    (b"Transfer-Encoding: chunked\r\n", b'15\r\n{"qrsig":1,"keys":[]}\r\n0\r\n\r\n'),
    (b"Content-Length: 20000\r\n", b"x" * 20000),
])
def test_fetch_accepts_complete_empty_documents_and_rejects_oversize(monkeypatch, headers, body):
    wire = b"HTTP/1.1 200 OK\r\n" + headers + b"\r\n" + body

    def open_response(request, timeout):
        assert request.full_url == "https://pay.example.com/.well-known/qrsig.json"
        response = http.client.HTTPResponse(SimpleNamespace(makefile=lambda mode: io.BytesIO(wire)))
        response.begin()
        return response

    monkeypatch.setattr(keys.urllib.request, "build_opener",
                        lambda *handlers: SimpleNamespace(open=open_response))
    assert keys.fetch("pay.example.com") == []
