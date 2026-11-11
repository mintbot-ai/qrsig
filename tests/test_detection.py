"""A detector can return non-QR candidates without QR metadata."""
from pathlib import Path
from types import SimpleNamespace

import zxingcpp
from qrsig import qr


def test_non_qr_result_without_metadata_does_not_hide_real_qr(monkeypatch):
    original = zxingcpp.read_barcodes
    def mixed(image, **options):
        return [SimpleNamespace(extra=None)] + original(image, **options)
    monkeypatch.setattr(zxingcpp, 'read_barcodes', mixed)
    scan = qr.read(Path(__file__).resolve().parents[1] / 'examples/signed-bitcoin.png')
    assert scan.payload.startswith(b'bitcoin:')
