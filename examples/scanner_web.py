#!/usr/bin/env python3
"""A QRSig scanner in one file: pick or photograph a QR code, see what it says
and who signed it.

    python examples/scanner_web.py                 # http://127.0.0.1:8765
    python examples/scanner_web.py --pin pay.example.com=examples/pay.example.com.qrsig.json

Offline by default: ``--pin`` uses a trusted document on disk. ``--online``
opts into HTTPS requests to signer-controlled domains (trusted inputs only;
not SSRF-hardened). The demo codes use the public test key for pay.example.com.
Never expose this demo as a public upload service.

Standard library plus qrsig[read]. A demo: it listens on localhost only.
"""
from __future__ import annotations

import argparse
import io
import json
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from qrsig import keys, qr  # noqa: E402

MAX_UPLOAD = 12 * 1024 * 1024
RESOLVER = keys.Resolver(offline=True)

PAGE = """<!doctype html>
<html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>QRSig scanner</title>
<style>
  body { font: 16px/1.5 system-ui, sans-serif; max-width: 34rem; margin: 2rem auto; padding: 0 1rem; color: #111827 }
  h1 { font-size: 1.3rem }
  label.pick { display: block; padding: 1.2rem; border: 2px dashed #9ca3af; border-radius: 12px; text-align: center; cursor: pointer }
  input[type=file] { display: none }
  #card { margin-top: 1.2rem; padding: 1rem; border-radius: 12px; border: 1px solid #d1d5db; display: none }
  #payload { font-family: ui-monospace, monospace; word-break: break-all; margin: .3rem 0 1rem }
  #verdict { font-weight: 600; padding: .6rem .8rem; border-radius: 8px }
  .verified { background: #dcfce7; color: #14532d }
  .invalid { background: #fee2e2; color: #7f1d1d }
  .unverifiable, .unsigned, .error { background: #f3f4f6; color: #374151 }
  small { color: #6b7280 }
</style>
<h1>QRSig scanner</h1>
<label class="pick">Choose or photograph a QR code
  <input id="file" type="file" accept="image/*" capture="environment"></label>
<div id="card">
  <small>The code says</small><div id="payload"></div>
  <div id="verdict"></div><small id="detail"></small>
</div>
<script>
const $ = (id) => document.getElementById(id);
$('file').addEventListener('change', async (event) => {
  const file = event.target.files[0];
  if (!file) return;
  const reply = await fetch('/verify', { method: 'POST', body: file });
  const r = await reply.json();
  $('card').style.display = 'block';
  $('payload').textContent = r.payload || '';
  const when = r.issued_at ? new Date(r.issued_at * 1000).toLocaleString() : '';
  const text = {
    verified: 'Signed by ' + r.domain,
    invalid: 'Warning: claims to be signed by ' + r.domain + ', but is not',
    unverifiable: 'Claims to be from ' + r.domain + ' (not checked)',
    unsigned: 'Not signed',
    error: 'No readable QR code: ' + (r.reason || ''),
  }[r.status];
  $('verdict').className = r.status;
  $('verdict').textContent = text;
  $('detail').textContent = r.status === 'verified' ? 'Issued ' + when : (r.status === 'error' ? '' : r.reason || '');
  event.target.value = '';
});
</script>
"""


class Handler(BaseHTTPRequestHandler):
    def _send(self, status: int, body: bytes, kind: str) -> None:
        self.send_response(status)
        self.send_header("Content-Type", kind)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:  # noqa: N802
        if self.path == "/":
            self._send(200, PAGE.encode(), "text/html; charset=utf-8")
        else:
            self._send(404, b"not found", "text/plain")

    def do_POST(self) -> None:  # noqa: N802
        if self.path != "/verify":
            return self._send(404, b"not found", "text/plain")
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            length = 0
        if not 0 < length <= MAX_UPLOAD:
            return self._send(413, b'{"status": "error", "reason": "picture missing or too large"}', "application/json")
        try:
            result = qr.check(io.BytesIO(self.rfile.read(length)), RESOLVER)
        except Exception as exc:  # noqa: BLE001 -- not a picture, no code, too damaged
            result = {"status": "error", "reason": str(exc)}
        self._send(200, json.dumps(result).encode(), "application/json")

    def log_message(self, format, *args) -> None:  # noqa: A002 -- quiet
        pass


def main(argv: list[str] | None = None) -> int:
    global RESOLVER
    parser = argparse.ArgumentParser(description="A QRSig scanner in the browser (demo, localhost only).")
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument("--pin", action="append", default=[], metavar="DOMAIN=FILE")
    parser.add_argument("--online", action="store_true", help="allow HTTPS requests to signer-controlled hosts; trusted inputs only")
    args = parser.parse_args(argv)
    RESOLVER = keys.Resolver(offline=not args.online)
    for item in args.pin:
        domain, _, path = item.partition("=")
        RESOLVER.pin(domain, Path(path).read_bytes())
    server = ThreadingHTTPServer(("127.0.0.1", args.port), Handler)
    print(f"QRSig scanner on http://127.0.0.1:{args.port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
