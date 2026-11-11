# Adding QRSig to a QR scanner

A scanner already does almost everything QRSig needs. It locates the code,
samples the modules, removes the mask, de-interleaves the codewords and runs
Reed-Solomon error correction. What comes out is the code's **data
codewords**. The scanner then parses segments until the terminator and
returns the text. The bytes after the terminator are thrown away.

QRSig needs those bytes. That is the only change in the decoder.

## 1. Keep the padding

In the bit stream parser, at the point where the terminator (mode `0000`) is
read, or where fewer than four bits remain:

```
payload  = bytes produced by the segments so far      (see below)
position = number of bits consumed, terminator included
padding  = data_codewords[ceil(position / 8) :]         # empty if no terminator was read
```

Return `payload` and `padding` next to the text you already return.

`payload` is the content as raw bytes, before any character set guessing:

- numeric segment: its digits as ASCII;
- alphanumeric segment: its characters as ASCII;
- byte segment: its bytes, unchanged.

If the code has a Kanji segment, FNC1 or structured append, skip QRSig: the
code is unsigned.

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
in about 150 lines, starting from the corners a detector reports.

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
- 3xx, 4xx or an invalid document: the domain has no keys.
- network error, timeout, 5xx: unavailable.

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
revocation. Keep pinned documents current. The web demo defaults to offline;
`--online` is an explicit opt-in for trusted inputs.

The reference image reader refuses unsupported modes/character sets and
malformed segments with a read error; it never labels them verified. A
full-purpose scanner can still show its own normally decoded content without
a QRSig badge.

## 4. Verify

```
if issued_at > now + 24 h:              -> invalid
if keys unavailable:                    -> unverifiable
message = "qrsig1\n" + head + payload
for key in keys:
    if key.not_before and issued_at < key.not_before: continue
    if key.not_after  and issued_at > key.not_after:  continue
    if ed25519_verify(key, signature, message):      -> verified
-> invalid
```

Ed25519 verification is in every platform's crypto library (CryptoKit,
Tink / BouncyCastle, WebCrypto, libsodium).

## 5. Show it

| Outcome | Show |
|---|---|
| verified | "Signed by **pay.example.com**", next to the content |
| invalid | A warning, before the user can act on the content |
| unverifiable | Nothing, or a neutral "claims to be from ..., not checked" |
| unsigned | Nothing |

Always show the domain; never a bare tick. If the content is a web link to a
different host than the signing domain, show both.

For a wallet, the useful rule is stricter than display: remember the domains
the user has paid before, and warn when a payment code is signed by a new
one, is invalid, or is unsigned where a signature was seen before.

## 6. Test

- `vectors.json`: your block parser and verifier must accept every case, and
  reject each after flipping any one bit of the payload or the block.
- `examples/signed-bitcoin.png` with `examples/pay.example.com.qrsig.json`
  as the key document for `pay.example.com`: verified.
- `examples/unsigned-bitcoin.png`: unsigned, same content.
- `python -m qrsig sign ...` makes more codes; `python -m qrsig verify`
  is a second opinion on yours.
