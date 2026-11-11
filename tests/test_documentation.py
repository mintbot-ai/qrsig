"""Keep the documented examples and v1 clarification cases executable."""
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from qrcode.util import BitBuffer
from qrsig import format as fmt, keys, qr

ROOT = Path(__file__).resolve().parents[1]
DOCS = [ROOT / name for name in (
    "README.md", "SPEC.md", "docs/EXPLAINED.md", "docs/SCANNERS.md", "CHANGELOG.md"
)]


@pytest.mark.parametrize("document", ["README.md", "docs/EXPLAINED.md"])
def test_documented_python_examples(document, tmp_path):
    shutil.copytree(ROOT / "examples", tmp_path / "examples")
    blocks = re.findall(r"```python\n(.*?)\n```", (ROOT / document).read_text(), re.S)
    assert blocks, "Expected a runnable Python example"
    for code in blocks:
        result = subprocess.run([sys.executable, "-c", code], cwd=tmp_path,
                                capture_output=True, text=True, timeout=30)
        assert result.returncode == 0, result.stdout + result.stderr
        if document == "docs/EXPLAINED.md":
            assert result.stdout.splitlines() == ["Original: True", "Changed: False"]


def test_documentation_relative_links_and_anchors():
    for document in DOCS:
        for link in re.findall(r"\[[^\]]*\]\(([^)]+)\)", document.read_text()):
            if "://" in link:
                continue
            path, _, anchor = link.partition("#")
            target = (document.parent / path).resolve() if path else document
            assert target.exists(), (document, link)
            if anchor:
                headings = re.findall(r"^#+ (.+)$", target.read_text(), re.M)
                slugs = {re.sub(r"[^\w -]", "", h.lower()).replace(" ", "-") for h in headings}
                assert anchor in slugs, (document, link, slugs)


def fixture_key():
    private = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
    public = keys.b64url_decode("A6EHv_POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg")
    return private, public


@pytest.mark.parametrize("issued,expected", [(0, fmt.VERIFIED), (1, fmt.INVALID)])
def test_zero_time_bound_is_inclusive_not_absent(issued, expected):
    private, public = fixture_key()
    block = fmt.sign(b"https://example.com/", "example.com", private, issued_at=issued)
    result = fmt.verify(b"https://example.com/", block,
                        lambda _: [fmt.Key(public, not_before=0, not_after=0)], now=1)
    assert result.status == expected


@pytest.mark.parametrize("ahead,expected,lookups", [
    (86400, fmt.VERIFIED, ["example.com"]),
    (86401, fmt.INVALID, []),
])
def test_future_time_boundary_precedes_key_discovery(ahead, expected, lookups):
    private, public = fixture_key()
    block = fmt.sign(b"x", "example.com", private, issued_at=100 + ahead)
    called = []
    def resolve(domain):
        called.append(domain)
        return [fmt.Key(public)]
    assert fmt.verify(b"x", block, resolve, now=100).status == expected
    assert called == lookups


def test_utf8_sequence_may_cross_byte_segment_boundaries():
    buf = BitBuffer()
    for byte in (0xc3, 0xa9):
        buf.put(4, 4)  # byte segment
        buf.put(1, 8)  # one byte, version 1
        buf.put(byte, 8)
    buf.put(0, 4)
    while len(buf) % 8:
        buf.put(0, 1)
    assert qr.split(bytes(buf.buffer), 1) == ("é".encode(), b"")


@pytest.mark.parametrize("bounds", [
    {"not_before": None, "not_after": None},
    {"not_before": -1, "not_after": 0},
    {"not_before": 2, "not_after": 1},
])
def test_documented_time_bound_forms_parse(bounds):
    _, public = fixture_key()
    doc = {"qrsig": 1, "keys": [{"key": keys.b64url(public), **bounds}]}
    parsed = keys.parse_document(json.dumps(doc).encode())
    assert parsed == [fmt.Key(public, bounds["not_before"], bounds["not_after"])]


def test_documented_json_example_is_a_real_key_document():
    examples = re.findall(r"```json\n(.*?)\n```", (ROOT / "SPEC.md").read_text(), re.S)
    assert examples
    for example in examples:
        assert keys.parse_document(example.encode())
