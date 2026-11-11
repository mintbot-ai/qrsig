"""QRSig v1, end to end. The key and the clock are fixed: every run draws the same codes."""
import json
from pathlib import Path

import pytest
import qrcode
import zxingcpp
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from PIL import ImageDraw, ImageFilter, ImageOps

from qrsig import cli, keys, qr
from qrsig import format as fmt

ROOT = Path(__file__).resolve().parents[1]
NOW = 1794268800
DOMAIN = "pay.example.com"
KEY = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
OTHER = Ed25519PrivateKey.from_private_bytes(bytes(range(1, 33)))

PAYLOADS = {
    "bitcoin": "bitcoin:bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh?amount=0.00123456",
    "monero": "monero:" + "4" * 95 + "?tx_amount=0.123456789012",
    "url": "https://example.com/invoice/8c1f?lang=et",
    "digits": "00123456789012345678901234567890",
    "uppercase": "HELLO WORLD 123 $%*+-./:",
    "text": "Tere, maailm! õäöü €",
}


def public(key) -> bytes:
    return key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)


def trust(**published):
    """keys_for: domain (dots as underscores) -> the keys it publishes."""
    table = {name.replace("_", "."): value for name, value in published.items()}
    return lambda domain: table.get(domain, [])


OURS = trust(pay_example_com=[fmt.Key(public(KEY))])


def block(payload=b"x", domain=DOMAIN, key=KEY, issued_at=NOW):
    return fmt.sign(payload, domain, key, issued_at=issued_at)


# -- the block ----------------------------------------------------------------

def test_the_block_layout():
    b = block()
    assert b[:2] == b"QS" and b[2] == 1
    assert int.from_bytes(b[3:7], "big") == NOW
    assert b[7] == len(DOMAIN) and b[8:8 + len(DOMAIN)] == DOMAIN.encode()
    assert len(b) == 8 + len(DOMAIN) + 64


def test_a_signed_payload_verifies_and_names_its_domain():
    result = fmt.verify(b"x", block() + b"\xec\x11\xec", OURS, now=NOW)
    assert (result.status, result.domain, result.issued_at) == ("verified", DOMAIN, NOW)


def test_a_signature_holds_for_its_own_payload_only():
    assert fmt.verify(b"y", block(b"x"), OURS, now=NOW).status == "invalid"


def test_a_signature_holds_under_the_domains_own_keys_only():
    assert fmt.verify(b"x", block(key=OTHER), OURS, now=NOW).status == "invalid"
    assert fmt.verify(b"x", block(), trust(), now=NOW).status == "invalid"  # the domain publishes nothing
    both = trust(pay_example_com=[fmt.Key(public(OTHER)), fmt.Key(public(KEY))])
    assert fmt.verify(b"x", block(), both, now=NOW).status == "verified"


def test_the_domain_and_the_time_are_signed_too():
    b = block()
    later = b[:3] + (NOW + 1).to_bytes(4, "big") + b[7:]
    assert fmt.verify(b"x", later, OURS, now=NOW + 9).status == "invalid"
    moved = b.replace(b"pay.example.com", b"pay.example.org")
    everyone = trust(pay_example_com=[fmt.Key(public(KEY))], pay_example_org=[fmt.Key(public(KEY))])
    result = fmt.verify(b"x", moved, everyone, now=NOW)
    assert (result.status, result.domain) == ("invalid", "pay.example.org")


def test_a_key_signs_only_inside_its_validity():
    def status(**bounds):
        return fmt.verify(b"x", block(), trust(pay_example_com=[fmt.Key(public(KEY), **bounds)]), now=NOW).status
    assert status(not_before=NOW, not_after=NOW) == "verified"
    assert status(not_before=NOW + 1) == "invalid"
    assert status(not_after=NOW - 1) == "invalid"


def test_a_code_from_the_future_is_invalid():
    assert fmt.verify(b"x", block(issued_at=NOW + 86400), OURS, now=NOW).status == "verified"
    assert fmt.verify(b"x", block(issued_at=NOW + 86401), OURS, now=NOW).status == "invalid"


def test_keys_that_cannot_be_fetched_are_no_verdict():
    def offline(domain):
        raise fmt.KeysUnavailable("offline")
    result = fmt.verify(b"x", block(), offline, now=NOW)
    assert (result.status, result.domain, result.reason) == ("unverifiable", DOMAIN, "offline")


@pytest.mark.parametrize("padding", [
    b"", b"\xec\x11" * 60, b"QS", b"QS\x02" + block()[3:], block()[:-1],
    b"QS\x01" + NOW.to_bytes(4, "big") + b"\x0bExample.com" + b"\x01" * 64,
    b"QS\x01" + NOW.to_bytes(4, "big") + b"\x09localhost" + b"\x01" * 64,
])
def test_other_padding_is_an_unsigned_code(padding):
    assert fmt.parse(padding) is None
    assert fmt.verify(b"x", padding, OURS, now=NOW) == fmt.Result("unsigned")


@pytest.mark.parametrize("domain,ok", [
    ("example.com", True), ("pay.example.com", True), ("xn--bcher-kva.example", True), ("a.io", True),
    ("Example.com", False), ("example.com.", False), ("example.com:443", False), ("localhost", False),
    ("-a.example.com", False), ("example.com/x", False), ("1.2.3.4", False), ("", False),
])
def test_what_a_domain_is(domain, ok):
    assert fmt.is_domain(domain) is ok
    if not ok:
        with pytest.raises(ValueError):
            fmt.sign(b"x", domain, KEY)


# -- the key document ---------------------------------------------------------

def test_the_published_document_round_trips():
    private, pub = keys.generate()
    assert keys.public_of(private) == pub
    doc = keys.document([pub, {"key": keys.b64url(public(KEY)), "not_after": NOW}])
    assert json.loads(doc)["qrsig"] == 1
    parsed = keys.parse_document(doc.encode())
    assert [k.public for k in parsed] == [keys.b64url_decode(pub), public(KEY)]
    assert (parsed[1].not_before, parsed[1].not_after) == (None, NOW)


@pytest.mark.parametrize("body", [
    b"not json", b"[]", b'{"qrsig": 2, "keys": []}', b'{"qrsig": 1}', b'{"qrsig": 1, "keys": ["x"]}',
    b'{"qrsig": 1, "keys": [{"key": "AAAA"}]}',
    json.dumps({"qrsig": 1, "keys": [{"key": keys.b64url(bytes(32)), "not_after": "soon"}]}).encode(),
    json.dumps({"qrsig": 1, "keys": [{"key": keys.b64url(bytes(32))}] * 17}).encode(),
    b" " * (keys.MAX_DOCUMENT_BYTES + 1),
])
def test_what_is_not_a_key_document(body):
    with pytest.raises(ValueError):
        keys.parse_document(body)


def test_the_resolver_fetches_once_and_prefers_what_it_was_handed():
    calls = []

    def fetch(domain):
        calls.append(domain)
        return [fmt.Key(public(KEY))]
    resolver = keys.Resolver(fetch=fetch)
    assert resolver(DOMAIN) == resolver(DOMAIN) == [fmt.Key(public(KEY))]
    assert calls == [DOMAIN]
    resolver.pin("other.example.com", keys.document([keys.b64url(public(OTHER))]).encode())
    assert resolver("other.example.com") == [fmt.Key(public(OTHER))] and calls == [DOMAIN]


def test_a_domain_that_is_none_is_never_fetched():
    assert keys.fetch("localhost") == []


# -- in a QR code -------------------------------------------------------------

def image(payload, ec="M", key=KEY, domain=DOMAIN):
    return qr.signed(payload, domain, key, issued_at=NOW, ec=ec).make_image().convert("RGB")


@pytest.mark.parametrize("name", sorted(PAYLOADS))
@pytest.mark.parametrize("ec", ["L", "M", "H"])
def test_a_scanner_reads_the_payload_and_we_read_the_signature(name, ec):
    payload = PAYLOADS[name]
    img = image(payload, ec)
    assert [r.text for r in zxingcpp.read_barcodes(img)] == [payload]
    result = qr.check(img, OURS, now=NOW)
    assert (result["payload"], result["status"], result["domain"], result["issued_at"]) == (payload, "verified", DOMAIN, NOW)


@pytest.mark.parametrize("name", sorted(PAYLOADS))
def test_zbar_reads_the_payload_too(name):
    """ZBar guesses the character set of non-ASCII bytes, signed or not: what
    matters is that it reads a signed code exactly as it reads a plain one."""
    pyzbar = pytest.importorskip("pyzbar.pyzbar")

    def zbar(img):
        return [f.data for f in pyzbar.decode(img.convert("L"), symbols=[pyzbar.ZBarSymbol.QRCODE])]
    signed = zbar(image(PAYLOADS[name]))
    assert len(signed) == 1 and signed == zbar(qr.make(PAYLOADS[name]).make_image().get_image())
    if PAYLOADS[name].isascii():
        assert signed == [PAYLOADS[name].encode()]


def test_the_payload_is_encoded_as_without_a_signature():
    """Signing changes the padding and, for room, the version: never the data."""
    for payload in PAYLOADS.values():
        plain = qr.read(qr.make(payload).make_image())
        signed = qr.read(image(payload))
        assert plain.payload == signed.payload == payload.encode("utf-8")
        assert fmt.parse(plain.padding) is None and fmt.parse(signed.padding) is not None


def test_ordinary_codes_are_unsigned():
    for img in (qr.make(PAYLOADS["url"]).make_image(), qrcode.make(PAYLOADS["url"])):
        result = qr.check(img, OURS, now=NOW)
        assert (result["payload"], result["status"], result["domain"]) == (PAYLOADS["url"], "unsigned", None)


def test_a_copied_block_does_not_sign_another_code():
    stolen = qr.read(image(PAYLOADS["bitcoin"])).padding[:8 + len(DOMAIN) + 64]
    forged = PAYLOADS["bitcoin"].replace("bc1qxy2", "bc1qevil")
    result = qr.check(qr.make(forged, stolen).make_image(), OURS, now=NOW)
    assert (result["payload"], result["status"], result["domain"]) == (forged, "invalid", DOMAIN)


def test_another_domains_key_does_not_sign_for_this_one():
    result = qr.check(image(PAYLOADS["bitcoin"], key=OTHER), OURS, now=NOW)
    assert result["status"] == "invalid"


def test_the_signature_survives_what_the_code_survives():
    img = image(PAYLOADS["bitcoin"])
    blot = img.copy()
    ImageDraw.Draw(blot).rectangle([160, 160, 189, 189], fill=(0, 0, 0))  # three modules square, in the data
    turned = img.rotate(90, expand=True).resize((img.width * 17 // 10,) * 2).filter(ImageFilter.GaussianBlur(1.5))
    inverted = ImageOps.invert(img)
    for picture in (blot, turned, inverted):
        assert qr.check(picture, OURS, now=NOW)["status"] == "verified"


def test_a_payload_with_no_room_left_is_refused_not_mangled():
    with pytest.raises(ValueError):
        qr.signed("k" * 2900, DOMAIN, KEY, ec="L")


# -- the published vectors and the command line -------------------------------

def test_the_published_vectors():
    vectors = json.loads((ROOT / "vectors.json").read_text())
    key = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(vectors["private_key_hex"]))
    published = keys.parse_document(json.dumps(vectors["document"]).encode())
    assert [k.public for k in published] == [public(key)]
    assert len(vectors["cases"]) >= 3
    for case in vectors["cases"]:
        payload = case["payload"].encode("utf-8")
        expected = bytes.fromhex(case["block_hex"])
        assert fmt.sign(payload, case["domain"], key, issued_at=case["issued_at"]) == expected
        assert fmt.message(expected[:-64], payload) == bytes.fromhex(case["signed_message_hex"])
        result = fmt.verify(payload, expected, lambda d, c=case: published if d == c["domain"] else [],
                            now=case["issued_at"])
        assert result.status == "verified"


def test_the_command_line(tmp_path, capsys, monkeypatch):
    key, doc, png = tmp_path / "key.json", tmp_path / "qrsig.json", tmp_path / "code.png"
    assert cli.main(["keygen", "-o", str(key)]) == 0
    doc.write_text(capsys.readouterr().out)
    assert key.stat().st_mode & 0o077 == 0
    assert cli.main(["sign", PAYLOADS["bitcoin"], "--domain", DOMAIN, "--key", str(key), "-o", str(png)]) == 0
    capsys.readouterr()
    assert cli.main(["verify", str(png), "--pin", f"{DOMAIN}={doc}", "--json"]) == 0
    out = json.loads(capsys.readouterr().out)
    assert (out["payload"], out["status"], out["domain"]) == (PAYLOADS["bitcoin"], "verified", DOMAIN)
    assert cli.main(["verify", str(png), "--pin", f"{DOMAIN}={doc}"]) == 0
    assert f"verified: signed by {DOMAIN}" in capsys.readouterr().out
    # Another document for the same domain: the code is not that domain's.
    doc.write_text(keys.document([keys.b64url(public(OTHER))]))
    assert cli.main(["verify", str(png), "--pin", f"{DOMAIN}={doc}"]) == 1
    assert "INVALID" in capsys.readouterr().out
    # The network is down: no verdict, and no success either.
    def offline(domain, **kw):
        raise fmt.KeysUnavailable("offline")
    monkeypatch.setattr(keys.Resolver.__init__, "__defaults__", (offline, keys.CACHE_SECONDS))
    assert cli.main(["verify", str(png)]) == 1
    assert "not checked" in capsys.readouterr().out
    assert cli.main(["verify", str(tmp_path / "missing.png")]) == 2


def test_no_single_flipped_bit_verifies():
    """Any one bit changed, in the payload or anywhere in the block."""
    case = json.loads((ROOT / "vectors.json").read_text())["cases"][0]
    payload, good = case["payload"].encode(), bytes.fromhex(case["block_hex"])
    assert fmt.verify(payload, good, OURS, now=NOW).status == "verified"

    def flipped(data, bit):
        out = bytearray(data)
        out[bit // 8] ^= 0x80 >> (bit % 8)
        return bytes(out)
    for bit in range(len(good) * 8):
        assert fmt.verify(payload, flipped(good, bit), OURS, now=NOW).status != "verified", bit
    for bit in range(len(payload) * 8):
        assert fmt.verify(flipped(payload, bit), good, OURS, now=NOW).status == "invalid", bit
