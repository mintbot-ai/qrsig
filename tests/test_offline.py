"""Offline verification must not fetch a signer-controlled URL."""
import importlib.util
import json
from pathlib import Path

import pytest

from qrsig import cli, keys
from qrsig.format import KeysUnavailable

ROOT = Path(__file__).resolve().parents[1]
DOMAIN = 'pay.example.com'
DOC = ROOT / 'examples/pay.example.com.qrsig.json'
IMAGE = ROOT / 'examples/signed-bitcoin.png'


def test_offline_resolver_uses_pins_and_never_fetches():
    def forbidden(domain):
        pytest.fail('offline resolver attempted network access')
    resolver = keys.Resolver(fetch=forbidden, offline=True)
    with pytest.raises(KeysUnavailable, match='offline'):
        resolver(DOMAIN)
    resolver.pin(DOMAIN, DOC.read_bytes())
    assert resolver(DOMAIN) == keys.parse_document(DOC.read_bytes())
    with pytest.raises(KeysUnavailable, match='offline'):
        resolver('other.example.com')


def test_offline_cli_reports_unverifiable_without_pin(capsys):
    assert cli.main(['verify', str(IMAGE), '--offline', '--json']) == 1
    assert json.loads(capsys.readouterr().out)['status'] == 'unverifiable'
    assert cli.main(['verify', str(IMAGE), '--offline', '--pin', f'{DOMAIN}={DOC}', '--json']) == 0
    assert json.loads(capsys.readouterr().out)['status'] == 'verified'


def test_web_demo_defaults_to_no_network():
    spec = importlib.util.spec_from_file_location('offline_scanner', ROOT / 'examples/scanner_web.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    with pytest.raises(KeysUnavailable, match='offline'):
        module.RESOLVER(DOMAIN)
