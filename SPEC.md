# QRSig 1: signed QR codes

Status: draft 1 (2026-11-11). Comments and implementations welcome.

## 1. What it is

A QR code can say who made it. The issuer signs the code's content with a key
its domain publishes; a scanner that knows QRSig checks the signature and
shows "signed by pay.example.com".

The signature is not part of the content. It sits in the code's **padding**,
the filler bytes a QR code carries after its data and that every reader
skips. So:

- the content is untouched: the URL, payment URI or text is exactly what it
  would be unsigned;
- a scanner that does not know QRSig reads the code as it reads any other;
- the code retains QR structure and error correction over all data codewords.

QRSig replaces the pad byte values prescribed by ISO/IEC 18004. It is a
reader-compatible extension in the implementations tested, not a claim that
the modified padding strictly conforms to that standard. Compatibility with
untested readers must be measured, not assumed.

The whole standard is three things: a **block** of bytes in the padding
(section 3), a **key document** on the issuer's domain (section 5) and a
**verification procedure** with four outcomes (section 6).

The key words MUST, MUST NOT, SHOULD and MAY are used as in RFC 2119.

## 2. Where the block lives

The data of a QR code (ISO/IEC 18004) is a bit stream: segments, then a
terminator of four zero bits, then zero bits up to the next codeword
boundary, then **pad codewords** (`EC 11 EC 11 ...`) up to the code's
capacity. Readers stop at the terminator.

A signed code replaces the first pad codewords with the block:

```
| segments | terminator 0000 | 0..7 zero bits | BLOCK | EC 11 EC 11 ... |
                                               ^ first whole codeword after the terminator
```

Rules for the issuer:

- The code MUST have the full four-bit terminator, and the block MUST start
  at the first codeword boundary after it.
- The issuer picks the smallest QR version in which data, terminator and
  block fit. Codewords after the block are the standard padding.
- Error correction codewords are computed over the final data codewords, as
  for any code. Any error correction level may be used.
- Segments MUST be numeric, alphanumeric or byte mode. Byte segments MUST
  hold UTF-8. Kanji mode, FNC1, structured append and Micro QR are out of
  scope: such codes are unsigned. An ECI designator, if present, MUST be
  UTF-8 (assignment 26); other character sets are out of scope. Malformed
  segment values or invalid UTF-8 MUST NOT yield a verified result.

## 3. The block

All integers are big-endian.

| Offset | Bytes | Field | Value |
|---|---|---|---|
| 0 | 2 | magic | `51 53` (ASCII `QS`) |
| 2 | 1 | version | `01` |
| 3 | 4 | issued at | Unix time in seconds, unsigned |
| 7 | 1 | domain length | *n*, 4 to 253 |
| 8 | *n* | domain | ASCII, see below |
| 8 + *n* | 64 | signature | Ed25519 (RFC 8032) |

The block is 72 + *n* bytes: 83 for `example.com`.

**Domain.** The host name whose keys sign the code: lowercase ASCII letters,
digits and hyphens in dot-separated labels, at least two labels, the last
one starting with a letter, 253 characters at most. No port, no path, no
trailing dot, no IP address. Internationalised names are written as A-labels
(`xn--...`).

## 4. What is signed

```
signature = Ed25519-Sign(private key, "qrsig1\n" || block[0 .. 8+n) || payload)
```

- `"qrsig1\n"` is seven ASCII bytes (`71 72 73 69 67 31 0a`). They keep a
  QRSig signature from being mistaken for a signature of anything else made
  with the same key.
- `block[0 .. 8+n)` is everything in the block before the signature. Magic,
  version, time and domain are therefore signed too.
- `payload` is the content of the code as bytes: the segments in order, a
  numeric or alphanumeric segment as its ASCII characters, a byte segment as
  its bytes. For a code made from a text string this is the string in UTF-8.

## 5. The key document

A domain that signs QR codes publishes its public keys at

```
https://<domain>/.well-known/qrsig.json
```

```json
{
  "qrsig": 1,
  "keys": [
    { "key": "A6EHv_POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg" },
    { "key": "...", "not_before": 1767225600, "not_after": 1798761600 }
  ]
}
```

- `key`: an Ed25519 public key, 32 bytes, base64url without padding.
- `not_before`, `not_after`: optional Unix times. The key signs only codes
  whose *issued at* lies within them (inclusive).
- At most 16 keys; the document is at most 16 KiB. Unknown members are
  ignored.

There are no key identifiers: a verifier tries each key. To rotate, add the
new key, sign with it, and give the old one a `not_after`; codes already
printed stay valid. To revoke, remove the key: every code it signed becomes
invalid.

Fetching:

- HTTPS only, with ordinary certificate validation. The fetch MUST NOT follow
  redirects: the keys are the domain's own, at this address.
- A 3xx or 4xx answer, or a body that is not a valid document, means **the
  domain publishes no keys**.
- A network failure, a timeout or a 5xx answer means **the keys are
  unavailable** just now.
- A verifier SHOULD cache a document, for 24 hours at most.

A subdomain is its own domain: `pay.example.com` publishes its own document
and `example.com` does not speak for it.

## 6. Verification

Input: the data codewords of the code after error correction.

1. Decode the segments to get the payload (section 4) and find the
   terminator. Take the bytes from the first codeword boundary after it: the
   padding.
2. If the padding does not start with `51 53 01`, or the block is malformed
   (too short, bad domain), or the code uses a mode outside section 2:
   **unsigned**. Stop.
3. If *issued at* is more than 24 hours ahead of the verifier's clock:
   **invalid**. Stop.
4. Get the domain's keys (section 5). If they are unavailable:
   **unverifiable**. Stop.
5. For each key whose validity covers *issued at*, verify the signature. If
   one verifies: **verified**. Otherwise, including when the domain
   publishes no keys: **invalid**.

| Outcome | Meaning |
|---|---|
| unsigned | An ordinary code. Nothing to say. |
| verified | A key published by the named domain signed this content and claimed issue time. |
| invalid | The claim fails current verification (tampering, wrong/removed key, or invalid time). |
| unverifiable | The claim could not be checked now. Not a success. |

A block of an unknown version is *unsigned*, so later versions do not break
today's scanners.

## 7. What a scanner shows

- **verified**: the domain, as prominently as the content: "Signed by
  pay.example.com". Never a bare tick or "verified" without the domain. The
  signature says who signed, not that they are trustworthy.
- **invalid**: a clear warning before any action (opening the link, filling
  in a payment).
- **unverifiable**: at most a neutral note ("claims to be from ..., not
  checked"). MUST NOT look like *verified*.
- **unsigned**: nothing. Most codes are unsigned; this is not a warning.
- When the content is an `http(s)` URL whose host is neither the signing
  domain nor a subdomain of it, the scanner SHOULD show both, so the
  difference is visible.
- The scanner MAY show the issue time, and MAY let applications apply their
  own rules (a wallet accepting payment codes only from domains the user has
  approved; a maximum age for login codes).

## 8. Notes for issuers

- **Size.** The block costs 72 bytes plus the domain name, which makes the
  code several versions larger. Measured with the reference implementation,
  for an 87-byte block (`pay.example.com`), modules per side unsigned →
  signed:

  | Content | L | M | Q | H |
  |---|---|---|---|---|
  | Bitcoin payment URI, 68 chars | 33 → 49 | 37 → 53 | 41 → 61 | 49 → 65 |
  | Monero payment URI, 127 chars | 33 → 49 | 37 → 53 | 45 → 61 | 49 → 69 |
  | URL, 40 chars | 29 → 41 | 29 → 49 | 33 → 53 | 37 → 61 |

  Show or print a signed code larger by the same factor, so that a module is
  as large as it was. A short domain and a lower error correction level keep
  the code small.
- **Keys.** Keep the private key where the codes are made and nowhere else.
  Use a key for QRSig only.
- **Signing failure.** An optional-origin badge MAY fall back to an unsigned
  code, explicitly reported as such. An application that requires authenticity
  MUST fail closed instead. The reference `qr.signed()` raises on failure;
  it never silently returns an unsigned code.

## 9. Security considerations

- **A signature names a domain; trust is the reader's.** Anyone can sign any
  content under a domain they control. `verified` under `evil.example` is a
  true statement about `evil.example`. This is why the domain must be shown
  (section 7), and why look-alike domains are as much a risk here as in
  links.
- **Copies are valid.** A signed code can be photographed and shown again.
  QRSig proves origin and integrity, not that this is the first or the
  intended showing. Content that must not be replayed needs its own
  single-use token or expiry, checked by the service; *issued at* lets a
  scanner apply a maximum age.
- **Stripping.** An attacker can remove the block; the code then reads as
  unsigned. A reader gains protection only where it expects a signature: a
  wallet that knows a merchant signs its codes can refuse an unsigned one.
- **The domain is the root of trust.** Whoever controls the web server or
  the DNS of a domain can publish keys for it. QRSig is as strong as the
  domain's HTTPS.
- **Revocation is by removal** and takes effect as caches expire (24 hours
  at most).
- **Clocks.** *Issued at* is the issuer's claim, not a trusted timestamp or
  expiry. A third party cannot change it, but an issuer (or someone with a
  stolen private key) can backdate a new code. `not_after` alone therefore
  cannot revoke a compromised key; remove the key.
- **Not secret.** The block is publicly readable. Neither private keys nor
  credentials belong there. A signature authenticates bytes; it does not
  encrypt them.
- **Network input is hostile.** A signing domain may resolve to private or
  loopback addresses. Server verifiers MUST restrict egress or use a transport
  that connects only to validated public destinations, including after DNS
  changes. A DNS pre-check followed by a fresh resolution is insufficient.
  The reference online resolver is not an SSRF boundary; use offline pins
  or a controlled network when handling untrusted images.

## 10. Privacy

Verifying a code makes the scanner fetch a document from the signing domain,
which tells that domain that someone, at that address, saw one of its codes.
The request carries nothing about the code itself. Scanners SHOULD cache, and
MAY fetch through a proxy or ship the keys of well-known issuers. A scanner
MAY let the user turn verification off.

## 11. Compatibility

The padding of a QR code is not interpreted by readers. With the reference
implementation, 300 signed codes with random keys and payloads were read by
ZXing (zxing-cpp) and by ZBar: 300 of 300 each, as plain black squares at
error correction M. Readers we have not run (Apple's and Google's among
them) are not covered by that measurement; reports are welcome.

Signing leaves the encoded data bits unchanged. It changes the padding and,
for room, the version; a denser code needs a larger picture to scan as
easily (section 8).

## 12. Test vectors

`vectors.json` holds the full set; implementations must reproduce each block
byte for byte (Ed25519 signatures are deterministic). The first:

```
private key  000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
public key   A6EHv_POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg   (base64url)
domain       pay.example.com
issued at    1794268800   (2026-11-10T00:00:00Z)
payload      bitcoin:bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh?amount=0.00123456

block
  51 53                                          magic
  01                                             version
  6a f2 5e 80                                    issued at
  0f                                             domain length
  70 61 79 2e 65 78 61 6d 70 6c 65 2e 63 6f 6d   "pay.example.com"
  8badc3e9c7b4b786fc41a94339cfce62e2cb5db9c4bd21a44b7d4761cb73405c
  26de234f7f5624c5d07b739d856e6a91a6308d30a290b7eed9b3c3400a07c80a   signature
```

`examples/signed-bitcoin.png` is this code as a picture, and
`examples/pay.example.com.qrsig.json` the matching key document.

## 13. Related work

QRSig is not the first way to sign what a barcode says. The others we know
put the signature inside the content, which then needs a reader that
understands the format, or rely on certificates rather than a domain's own
web server.

- ISO/IEC 20248 (DigSig): signed data structures for barcodes and RFID,
  built on X.509 certificates. <https://www.iso.org/standard/67412.html>
- Signed health certificates (EU Digital COVID Certificate, SMART Health
  Cards): COSE or JWS envelopes as the QR content.
- K. Fukuchi, "Embedding Secret Data in QR Code": on carrying extra data in
  a QR code's padding. <https://fukuchi.org/en/works/qrhack/qrhack1>
- "Secure QR Codes: Authenticity Verification via EdDSA Signatures and CBOR
  Certificates". <https://arxiv.org/html/2607.08383>

The model for key discovery is the one mail uses for DKIM: the domain
publishes the key, the reader fetches it, and the reader shows the domain.
