"""QRSig v1: a domain's keys (SPEC.md, section 5).

A domain says which keys sign its codes in one small JSON document at
``https://<domain>/.well-known/qrsig.json``.
"""
from __future__ import annotations

import base64
import http.client
import json
import time
import urllib.error
import urllib.request

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat, PublicFormat

from .format import Key, KeysUnavailable, is_domain

WELL_KNOWN = "/.well-known/qrsig.json"
MAX_KEYS = 16
MAX_DOCUMENT_BYTES = 16 * 1024
CACHE_SECONDS = 3600


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64url_decode(text: str) -> bytes:
    decoded = base64.b64decode(text + "=" * (-len(text) % 4), altchars=b"-_", validate=True)
    if b64url(decoded) != text:
        raise ValueError("not canonical unpadded base64url")
    return decoded


def generate() -> tuple[str, str]:
    """A new key pair: (private, public), each 32 bytes as base64url."""
    key = Ed25519PrivateKey.generate()
    return (b64url(key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())),
            b64url(key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)))


def private_key(text: str) -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(b64url_decode(text))


def public_of(private: str) -> str:
    return b64url(private_key(private).public_key().public_bytes(Encoding.Raw, PublicFormat.Raw))


def document(public_keys: list[str | dict]) -> str:
    """The JSON a domain publishes. Each key is its base64url text, or a dict
    with ``key`` and optionally ``not_before`` / ``not_after``."""
    keys = [{"key": k} if isinstance(k, str) else k for k in public_keys]
    parse_document(json.dumps({"qrsig": 1, "keys": keys}).encode())  # refuse to write what no one would read
    return json.dumps({"qrsig": 1, "keys": keys}, indent=2) + "\n"


def _reject_json_constant(value: str) -> None:
    raise ValueError(f"non-standard JSON constant: {value}")


def parse_document(body: bytes) -> list[Key]:
    """The keys of a published document. ``ValueError`` when it is not one."""
    if len(body) > MAX_DOCUMENT_BYTES:
        raise ValueError("document too large")
    try:
        doc = json.loads(body.decode("utf-8"), parse_constant=_reject_json_constant)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("not JSON") from exc
    if (not isinstance(doc, dict) or type(doc.get("qrsig")) is not int
            or doc["qrsig"] != 1 or not isinstance(doc.get("keys"), list)):
        raise ValueError("not a qrsig 1 document")
    if len(doc["keys"]) > MAX_KEYS:
        raise ValueError("too many keys")
    keys = []
    for item in doc["keys"]:
        if not isinstance(item, dict) or not isinstance(item.get("key"), str):
            raise ValueError("a key entry needs a 'key'")
        try:
            public = b64url_decode(item["key"])
        except ValueError as exc:
            raise ValueError("a key is not base64url") from exc
        if len(public) != 32:
            raise ValueError("a key is not 32 bytes")
        bounds = []
        for name in ("not_before", "not_after"):
            value = item.get(name)
            if value is not None and (isinstance(value, bool) or not isinstance(value, int)):
                raise ValueError(f"{name} is not unix seconds")
            bounds.append(value)
        keys.append(Key(public, *bounds))
    return keys


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):  # the keys are the domain's own, at this address
        return None


def fetch(domain: str, *, timeout: float = 5.0) -> list[Key]:
    """The keys *domain* publishes now. An empty list when it publishes none
    (no such file, a redirect, a document that is not one): the domain signs
    nothing. ``KeysUnavailable`` when we could not find out."""
    if not is_domain(domain):
        return []
    opener = urllib.request.build_opener(_NoRedirect)
    request = urllib.request.Request(f"https://{domain}{WELL_KNOWN}", headers={"Accept": "application/json"})
    try:
        with opener.open(request, timeout=timeout) as response:
            body = response.read(MAX_DOCUMENT_BYTES + 1)
            # HTTPResponse.read(amount) does not raise for a short Content-Length
            # body. Its remaining length distinguishes EOF from our size cutoff.
            if len(body) <= MAX_DOCUMENT_BYTES and response.length:
                raise http.client.IncompleteRead(body, response.length)
    except urllib.error.HTTPError as exc:
        if 300 <= exc.code < 500:
            return []
        raise KeysUnavailable(f"{domain} answered {exc.code}") from exc
    except (urllib.error.URLError, OSError, http.client.HTTPException) as exc:
        raise KeysUnavailable(f"{domain} could not be reached") from exc
    try:
        return parse_document(body)
    except ValueError:
        return []


class Resolver:
    """``keys_for`` for ``format.verify``: fetches a domain's keys and keeps
    them for an hour. Documents handed in with ``pin`` are used as they are,
    without the network. ``offline=True`` refuses ALL unpinned domains.
    Online fetching is not an SSRF boundary; server callers need controlled
    egress. Pins are local trust decisions and do not refresh revocation."""

    def __init__(self, fetch=fetch, cache_seconds: float = CACHE_SECONDS, *, offline: bool = False):
        self._fetch = fetch
        self._offline = offline
        self._cache_seconds = cache_seconds
        self._pinned: dict[str, list[Key]] = {}
        self._cached: dict[str, tuple[float, list[Key]]] = {}

    def pin(self, domain: str, body: bytes) -> None:
        self._pinned[domain] = parse_document(body)

    def __call__(self, domain: str) -> list[Key]:
        if domain in self._pinned:
            return self._pinned[domain]
        if self._offline:
            raise KeysUnavailable("offline: no pinned keys for this domain")
        kept = self._cached.get(domain)
        if kept and time.monotonic() - kept[0] < self._cache_seconds:
            return kept[1]
        keys = self._fetch(domain)
        self._cached[domain] = (time.monotonic(), keys)
        return keys
