"""QRSig v1: the signature block and how it is verified (SPEC.md, sections 3 to 6).

Nothing here knows about QR codes or the network. A block is bytes; the
payload is bytes; the keys of a domain come from a callable.
"""
from __future__ import annotations

import re
import struct
import time
from dataclasses import dataclass
from typing import Callable, Iterable

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

MAGIC = b"QS"
VERSION = 1
CONTEXT = b"qrsig1\n"
SIGNATURE_BYTES = 64
MAX_FUTURE = 86400  # a code may be issued at most a day ahead of the verifier's clock

UNSIGNED = "unsigned"
VERIFIED = "verified"
INVALID = "invalid"
UNVERIFIABLE = "unverifiable"

_HEAD = struct.Struct(">2sBIB")  # magic, version, issued at, domain length
_LABEL = r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
_DOMAIN = re.compile(rf"(?=.{{4,253}}$)(?:{_LABEL}\.)+[a-z](?:[a-z0-9-]{{0,61}}[a-z0-9])?")


class KeysUnavailable(Exception):
    """The domain's keys could not be fetched just now (offline, a timeout,
    a server error). Not a verdict on the code."""


@dataclass(frozen=True)
class Key:
    public: bytes                    # 32 bytes, Ed25519
    not_before: int | None = None    # unix seconds; codes issued earlier are not this key's
    not_after: int | None = None     # unix seconds; codes issued later are not this key's


@dataclass(frozen=True)
class Block:
    domain: str
    issued_at: int
    head: bytes        # everything before the signature: it is signed too
    signature: bytes


@dataclass(frozen=True)
class Result:
    status: str                      # unsigned | verified | invalid | unverifiable
    domain: str | None = None        # as claimed; a fact only when status is verified
    issued_at: int | None = None     # likewise
    reason: str = ""


def is_domain(domain: str) -> bool:
    """A lowercase ASCII host name (IDNs as A-labels): no port, no path, no dot at the end."""
    return isinstance(domain, str) and _DOMAIN.fullmatch(domain) is not None


def message(head: bytes, payload: bytes) -> bytes:
    """What is signed."""
    return CONTEXT + bytes(head) + bytes(payload)


def sign(payload: bytes, domain: str, private_key: Ed25519PrivateKey, *, issued_at: float | None = None) -> bytes:
    """The block to hide in the padding of a code that carries *payload*."""
    if not is_domain(domain):
        raise ValueError(f"not a domain: {domain!r}")
    name = domain.encode("ascii")
    head = _HEAD.pack(MAGIC, VERSION, int(time.time() if issued_at is None else issued_at), len(name)) + name
    return head + private_key.sign(message(head, payload))


def parse(padding: bytes) -> Block | None:
    """The block a code's padding starts with, or None: ordinary padding,
    another version, or anything malformed. All three are an unsigned code."""
    padding = bytes(padding)
    if len(padding) < _HEAD.size or padding[:2] != MAGIC:
        return None
    _, version, issued_at, length = _HEAD.unpack_from(padding)
    end = _HEAD.size + length
    if version != VERSION or len(padding) < end + SIGNATURE_BYTES:
        return None
    try:
        domain = padding[_HEAD.size:end].decode("ascii")
    except UnicodeDecodeError:
        return None
    if not is_domain(domain):
        return None
    return Block(domain, issued_at, padding[:end], padding[end:end + SIGNATURE_BYTES])


def verify(payload: bytes, padding: bytes, keys_for: Callable[[str], Iterable[Key]], *,
           now: float | None = None) -> Result:
    """Whose code this is. *keys_for* returns the keys a domain publishes
    (an empty list when it publishes none) or raises KeysUnavailable."""
    block = parse(padding)
    if block is None:
        return Result(UNSIGNED)
    claimed = {"domain": block.domain, "issued_at": block.issued_at}
    if block.issued_at > (time.time() if now is None else now) + MAX_FUTURE:
        return Result(INVALID, reason="issued in the future", **claimed)
    try:
        keys = list(keys_for(block.domain))
    except KeysUnavailable as exc:
        return Result(UNVERIFIABLE, reason=str(exc) or "keys unavailable", **claimed)
    signed = message(block.head, payload)
    for key in keys:
        if key.not_before is not None and block.issued_at < key.not_before:
            continue
        if key.not_after is not None and block.issued_at > key.not_after:
            continue
        try:
            Ed25519PublicKey.from_public_bytes(key.public).verify(block.signature, signed)
        except (InvalidSignature, ValueError):
            continue
        return Result(VERIFIED, **claimed)
    return Result(INVALID, reason=f"no key published by {block.domain} signs this code", **claimed)
