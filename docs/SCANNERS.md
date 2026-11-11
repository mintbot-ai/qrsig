# Adding QRSig to a QR scanner

[Website & interactive demo](https://qrsig.org/) · [Specification](../SPEC.md)

The path is **QR → exact bytes → domain keys → signature check → display**.
The website's M/S/K view illustrates the cryptographic step; this guide covers
the complete scanner flow, including failures.

A scanner already does almost everything QRSig needs. It locates the code,
samples the modules, removes the mask, de-interleaves the codewords and runs
Reed-Solomon error correction. What comes out is the code's **data
codewords**. The scanner then parses segments until the terminator and
returns the text. The bytes after the terminator are thrown away.

QRSig needs those bytes as well as the exact payload bytes. Preserve both
from the same error-corrected stream; do not pair text from one scan with
padding from another. The segment parser must also enforce the supported
modes and byte rules below.

## 1. Keep the padding

In the bit stream parser, retain the position just after a full four-bit
terminator (mode `0000`). If no full terminator was read, there is no QRSig
padding to inspect:

```
payload  = bytes produced by the segments so far      (see below)
position = number of bits consumed, terminator included
padding  = data_codewords[ceil(position / 8) :] if full_terminator else empty_bytes
```

Return `payload` and `padding` next to the text you already return.

`payload` is the content as raw bytes, before any character set guessing:

- numeric segment: its digits as ASCII;
- alphanumeric segment: its characters as ASCII;
- byte segment: its bytes, unchanged.

Only UTF-8 ECI (assignment 26) is supported. Concatenate the segment content
bytes, then validate UTF-8; a multibyte sequence may cross byte-segment
boundaries. Do not normalize text or silently replace malformed bytes.
Segment metadata, including ECI, is not part of the payload.

If the code has Kanji, FNC1, structured append or another ECI, it is outside
QRSig v1. A general-purpose scanner may still display its ordinary content,
but must not claim QRSig authentication. Micro QR is also out of scope.

Most decoders have this spot in one function. Pointers, from reading the
sources (check them against the version you ship):

- **ZXing** (Java and zxing-cpp): `DecodedBitStreamParser.decode` receives
  the corrected data codewords and loops over segments until the terminator.
- **quirc**: `decode_payload` walks the corrected data stream the same way.
- **ZBar**: the QR decoder's data parsing in `qrdectxt.c` / `qrdec.c`.

Platform scanners that return only text (Apple Vision, Google ML Kit, the
browser `BarcodeDetector`) cannot expose the padding to an app today. An app
on those platforms needs its own decoder for the QRSig step, or support from
the platform. `qrsig/qr.py` in this repository shows the whole reading path
starting from the corners a detector reports.

## 2. Parse the block

```
if padding[0:3] != 51 53 01:            -> unsigned
issued_at = uint32 big-endian at padding[3:7]
n         = padding[7]
domain    = padding[8 : 8+n]            ASCII; must be a valid lowercase host name
signature = padding[8+n : 8+n+64]
head      = padding[0 : 8+n]
anything missing or malformed          -> unsigned
```

## 3. Get the domain's keys

`GET https://<domain>/.well-known/qrsig.json`, no redirects, a timeout of a
few seconds. Cache the answer per domain, 24 hours at most.

- 200 with a valid document: its keys.
- 3xx, 4xx (including 404/429), malformed or oversized document: no keys.
- network/TLS error, timeout, incomplete transfer or 5xx: unavailable.

Validate the entire document against [section 5](../SPEC.md#5-the-key-document),
including canonical 32-byte keys and integer time bounds. One malformed
entry invalidates the document, rather than being silently skipped.

The content can be displayed immediately, but do not enable payment or
automatic navigation before checking the application's expected-signer policy.

The reference resolver uses HTTPS, certificate checks, no redirects, a
per-operation timeout and a bounded document size. It is NOT SSRF-safe:
DNS can point a syntactically valid domain at internal addresses, and urllib
uses configured environment proxies. Do not expose online verification as a
public upload service without controlled egress, connection-bound destination
validation, total deadlines, upload/pixel limits and concurrency/rate limits.
A preflight DNS lookup alone does not prevent DNS rebinding.

Use `keys.Resolver(offline=True)` or `qrsig verify --offline --pin DOMAIN=FILE`
for no network access. An unpinned signer is then `unverifiable`. A pin is a
local trust decision; it neither proves live domain control nor refreshes
revocation. Keep pinned documents current. The local `examples/scanner_web.py` demo defaults to offline;
`--online` is an explicit opt-in for trusted inputs.

The reference image reader refuses unsupported modes/character sets and
malformed segments with a read error; it never labels them verified. A
full-purpose scanner can still show its own normally decoded content without
a QRSig badge.

## 4. Verify

Check the future-time limit **before making a network request**. With a
well-formed block and supported payload, the rest is:

```text
if issued_at > now + 86400:                         -> invalid
keys = resolve(domain)                              # section 3
if keys unavailable:                               -> unverifiable
M = ASCII("qrsig1\n") || head || payload
S = signature                                       # 64 raw bytes
for entry in keys:
    if entry.not_before is not null and issued_at < entry.not_before: continue
    if entry.not_after  is not null and issued_at > entry.not_after:  continue
    K = base64url_decode(entry.key)                  # 32 raw bytes
    if Ed25519.verify(K, S, M):                     -> verified
-> invalid
```

This is pseudocode, not a particular library API. Bounds are inclusive;
`0` is a timestamp, not an omitted bound. Empty keys or no eligible keys
produce `invalid` without a successful signature check. A lookup that could
not complete produces `unverifiable`, not a cryptographic `false`.

Use an Ed25519 implementation such as your platform crypto API or libsodium.
Check runtime support: unavailable crypto is not a failed signature, and
must never be displayed as success. Use raw bytes for `M`, `S` and `K`, not
hex/base64 text. The [worked example](EXPLAINED.md#three-inputs-one-signature-check)
shows a real check and a changed-message failure.

## 5. Show it

| Outcome | Show |
|---|---|
| verified | "Signed by **pay.example.com**", next to the content |
| invalid | A warning, before the user can act on the content |
| unverifiable | Nothing, or a neutral "claims to be from ..., not checked" |
| unsigned | Nothing |

For an educational or diagnostic UI, keep M, S and K compact and let the
user expand their exact contents. Show the actual key that matched, its
encoding and fetched URL. If showing `true`/`false`, label it as the
cryptographic result, not the four-state QRSig outcome. Changing a displayed
address must also change the bytes being checked; do not reuse a previous
success while input is changing or a new check is pending.

Always show the domain; never a bare tick. If the content is a web link to a
different host than the signing domain, show both.

For a wallet, the useful rule is stricter than display: remember the domains
the user has paid before, and warn when a payment code is signed by a new
one, is invalid, or is unsigned where a signature was seen before.

## 6. Test

- `vectors.json`: reproduce the block bytes and accept valid cases. A
  one-bit change in payload or block must never produce `verified`; a broken
  header can yield `unsigned` rather than `invalid`.
- Cover missing/empty keys, a wrong key before the matching key, zero-valued
  and boundary timestamps, malformed documents, 404 vs timeout, and
  byte-segment boundaries within UTF-8 sequences.
- `examples/signed-bitcoin.png` with `examples/pay.example.com.qrsig.json`
  as the key document for `pay.example.com`: verified.
- `examples/unsigned-bitcoin.png`: unsigned, same content.
- `python -m qrsig sign ...` makes more codes; `python -m qrsig verify`
  is a second opinion on yours.
