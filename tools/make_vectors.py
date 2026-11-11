#!/usr/bin/env python3
"""Writes vectors.json: blocks any implementation must reproduce byte for byte
(Ed25519 signatures are deterministic). The private key is a test key."""
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402

from qrsig import format as fmt  # noqa: E402
from qrsig import keys  # noqa: E402

PRIVATE = bytes(range(32))
ISSUED_AT = 1794268800  # 2026-11-10T00:00:00Z
CASES = [
    ("bitcoin:bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh?amount=0.00123456", "pay.example.com"),
    ("https://example.com/invoice/8c1f?lang=et", "example.com"),
    ("Tere, maailm! \u00f5\u00e4\u00f6\u00fc \u20ac", "xn--bcher-kva.example"),
    ("", "example.com"),
]


def build() -> dict:
    key = Ed25519PrivateKey.from_private_bytes(PRIVATE)
    public = keys.public_of(keys.b64url(PRIVATE))
    cases = []
    for payload, domain in CASES:
        block = fmt.sign(payload.encode("utf-8"), domain, key, issued_at=ISSUED_AT)
        cases.append({"payload": payload, "payload_hex": payload.encode("utf-8").hex(), "domain": domain,
                      "issued_at": ISSUED_AT, "signed_message_hex": fmt.message(block[:-64], payload.encode("utf-8")).hex(),
                      "block_hex": block.hex()})
    return {"qrsig": 1, "private_key_hex": PRIVATE.hex(), "document": {"qrsig": 1, "keys": [{"key": public}]},
            "cases": cases}


if __name__ == "__main__":
    (ROOT / "vectors.json").write_text(json.dumps(build(), indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print("vectors.json written")
