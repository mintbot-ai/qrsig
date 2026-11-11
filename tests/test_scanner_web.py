"""The demo scanner answers over HTTP what the library answers directly."""
import importlib.util
import json
import threading
import urllib.request
from http.server import ThreadingHTTPServer
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def scanner():
    spec = importlib.util.spec_from_file_location("scanner_web", ROOT / "examples/scanner_web.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    module.RESOLVER.pin("pay.example.com", (ROOT / "examples/pay.example.com.qrsig.json").read_bytes())
    server = ThreadingHTTPServer(("127.0.0.1", 0), module.Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{server.server_address[1]}"
    server.shutdown()


def _post(base, body):
    request = urllib.request.Request(base + "/verify", data=body, method="POST")
    with urllib.request.urlopen(request, timeout=20) as reply:
        return json.loads(reply.read())


def test_the_demo_scanner(scanner):
    with urllib.request.urlopen(scanner + "/", timeout=20) as reply:
        assert b"QRSig scanner" in reply.read()
    signed = _post(scanner, (ROOT / "examples/signed-bitcoin.png").read_bytes())
    assert (signed["status"], signed["domain"], signed["issued_at"]) == ("verified", "pay.example.com", 1794268800)
    assert signed["payload"].startswith("bitcoin:bc1qxy2")
    plain = _post(scanner, (ROOT / "examples/unsigned-bitcoin.png").read_bytes())
    assert (plain["status"], plain["payload"]) == ("unsigned", signed["payload"])
    assert _post(scanner, b"not a picture")["status"] == "error"
