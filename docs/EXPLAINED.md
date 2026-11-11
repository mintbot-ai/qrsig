# What is actually inside a signed QR code?

[Explore the interactive example on qrsig.org](https://qrsig.org/) ·
[Specification](../SPEC.md) · [Scanner guide](SCANNERS.md)

A useful mental model: **the usual instruction, plus an origin seal**.
The seal is not another URL and does not change the payment address.
It is hidden from the ordinary scanner's text output, **not encrypted or secret**.

## One real example from this repository

The ordinary content of `examples/signed-bitcoin.png` is these 68 UTF-8 bytes:

```text
bitcoin:bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh?amount=0.00123456
```

This is a demonstration URI, not an instruction to send money. The address and
amount are in the ordinary content. A compatible ordinary QR reader returns
that URI; it does not show the signature block.

After the content's terminator and byte-alignment bits, QRSig stores:

| Bytes | Meaning | This example |
|---|---|---|
| 2 | Format marker | `QS` (`51 53` in hex) |
| 1 | Format version | `01` |
| 4 | Issuer's claimed creation time | `1794268800`, 2026-11-10 00:00 UTC |
| 1 | Domain length | 15 |
| 15 | Signing domain | `pay.example.com` |
| 64 | Ed25519 signature | Binary signature over the header and exact content |
| **87** | **Total extra block** | **72 fixed bytes + 15-byte domain** |

The 64-byte signature itself is not a compressed document containing the
merchant name or address. The domain and time are separate fields in the
signed block; the signature binds them to the exact ordinary content. There
is no private key, certificate, public key, second payment address or secret
message in this block. Version 1 fixes the algorithm to Ed25519; no separate
algorithm field is needed. Public keys are obtained separately.

The signed message is precisely:

```text
ASCII "qrsig1\n" + block header (marker/version/time/domain length/domain) + payload bytes
```

The context prefix is included in the signed message, not repeated inside
the QR block. See [SPEC.md](../SPEC.md) for the complete hex vector and
[the Ed25519 specification](https://www.rfc-editor.org/rfc/rfc8032).

## Where is the hidden information in the picture?

It is not a watermark in the logo, colour or white border. A decoder first
reconstructs the QR data codewords and corrects damage. The logical stream is:

```text
ordinary content | terminator | alignment zeroes | QRSig block | remaining filler
```

An ordinary reader stops at the terminator. A QRSig-aware reader keeps the
following bytes too. Error-correction codewords are calculated over the
complete data, including the block. Modules are interleaved and masked, so
there is no neat little rectangle that contains just the signature.

QRSig substitutes data for the usual alternating `EC 11` filler bytes
([reference QR encoder](https://github.com/lincolnloop/python-qrcode/blob/main/qrcode/util.py)).
This is a draft extension, not a promise of strict QR padding conformance or
support by every phone. The signature also consumes capacity: a larger QR
version usually means the image should be displayed larger.

## Three inputs. One signature check.

| Input | Repository fixture | Source |
|---|---|---|
| **M — message** | 98 bytes: 7-byte context + 23-byte header + 68-byte payload | Reconstructed from the QR and fixed context |
| **S — signature** | 64 raw bytes | The QR's hidden block |
| **K — public key** | 32 raw bytes | HTTPS key document, or an explicit trusted pin |

```text
Ed25519.verify(K, S, M) → true or false
```

The key document encodes K as unpadded base64url; decode it before checking.
The UI may show S and M as hex, but the crypto operation receives their raw
bytes. A signature's 128 hex characters are only a display of 64 bytes.

Changing the address changes M. Keep S and K unchanged and the check fails.
Switching back restores the original message and the original result.
This authenticates bytes, not whether a Bitcoin address is valid for payment
or belongs to the issuer.

<details>
<summary>Run the exact check in Python</summary>

Run from the repository root after installing the `read` extra. This reads
the actual PNG; it does not use a hardcoded verification result.

```python
from pathlib import Path
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from qrsig import format as fmt, keys, qr

scan = qr.read("examples/signed-bitcoin.png")
block = fmt.parse(scan.padding)
assert block is not None
M = fmt.message(block.head, scan.payload)
S = block.signature
K = keys.parse_document(Path("examples/pay.example.com.qrsig.json").read_bytes())[0].public

def matches(message):
    try:
        Ed25519PublicKey.from_public_bytes(K).verify(S, message)
    except InvalidSignature:
        return False
    return True

changed = fmt.message(block.head, scan.payload.replace(b"bc1q", b"bc1p", 1))
print("Original:", matches(M))       # Original: True
print("Changed:", matches(changed))  # Changed: False
assert len(M) == 98 and len(S) == 64 and len(K) == 32
```

This is the cryptographic step only, using the repository's public test key.
It does not fetch keys or apply their validity windows. The complete QRSig
check follows below.

</details>

## From a signature match to a QRSig outcome

1. Read the ordinary content and the hidden block from the same picture.
2. Read the claimed signing domain and time. Reject a time more than
   24 hours in the future before making a key request.
3. Obtain its public keys from `https://<domain>/.well-known/qrsig.json` over
   certificate-validated HTTPS without redirects, or use a trusted local pin.
4. Reconstruct the signed message and check it with keys eligible for the
   claimed issue time.
5. Show **which domain** verified, then apply the application's trust policy.

The Ed25519 boolean is not interchangeable with the protocol outcome. A
missing key document is `invalid`; a lookup that cannot complete is
`unverifiable`. No eligible key also means `invalid`, even if no Ed25519
operation ran. A diagnostic UI should say “not checked”, not claim a
cryptographic `false`, in that last case.

A public key can check a signature but cannot create a new valid signature.
The private key stays with the issuer. Anyone with the picture can inspect
all the information above; hiding is not access control.

Try the shipped fixture without any network access:

```sh
qrsig verify examples/signed-bitcoin.png --offline --pin pay.example.com=examples/pay.example.com.qrsig.json
qrsig verify examples/unsigned-bitcoin.png --offline
```

The first reports `verified`, the second `unsigned`. The example domain is
not queried. The fixture's private key is deliberately public in
`vectors.json`; never reuse it for real codes. A local pin establishes trust
in the supplied key, not proof that you contacted the real domain.

## Three changes, three different meanings

| What happens | Result | Why |
|---|---|---|
| Copy the entire original picture | `verified` | The signed bytes are unchanged; this is not copy protection. |
| Change `amount=0.00123456` to `amount=0.10123456`, retain the old block | `invalid` | The signature no longer matches the content. |
| Re-encode the original URI without the block | `unsigned` | Ordinary content survives, origin evidence does not. |

A fourth outcome, `unverifiable`, means the keys could not be obtained (for
example offline with no pin). It must not appear as success. `invalid` does
not necessarily prove a forgery: a removed signing key can cause it too.

## Can the signature be shorter?

QRSig v1 fixes Ed25519 signatures at **64 raw bytes**. Changing the UI from
hex to base64 does not save QR space: the block already stores bytes, not
text. Do not truncate the signature; the v1 parser and verifier require the
full value.

A different algorithm would require a separately specified format/version
and matching reader support. Before adding that complexity, measure whether
its byte saving actually crosses a QR-version boundary for the intended
payload and error-correction level. The whole block, not just S, occupies
capacity; a shorter domain also reduces it. A smaller byte count does not
necessarily produce a smaller module grid.

## Why this can be useful

### Payment codes and invoices

A wallet can say: "This address and amount were signed by the merchant domain
you expected." Replacing the address while keeping the signature fails.
Replacing the entire code with one signed by an attacker's domain only helps
the attacker if the wallet treats **any** valid domain as trusted. Match the
expected merchant, and reject missing signatures where one is required.

### Parking meters and printed service codes

An app that already knows the operator's domain can detect a substituted
sticker with an unsigned or differently signed payment instruction. A valid
code copied from another meter still needs the meter/location identifier and
server-side checks. QRSig alone does not bind a sticker to a physical place.

### Login and device pairing

A client can require a code signed by the expected service or agent domain
before using its pairing token. Tokens still need expiry, one-time redemption
and session binding. The signature is not authentication of the person who
holds or photographs the QR code.

### Tickets and product labels

A verifier can authenticate the issuer and unchanged ticket/product data.
Whether a ticket is unused, or a physical product is genuine rather than
wearing a copied label, needs an additional system. Copies remain valid.

## The limits worth remembering

- A signature is not encryption, a trusted timestamp, a payment receipt or a
  guarantee that the link is safe. The issuer chooses the signed time.
- An attacker with a stolen private key can backdate new codes. Remove the
  compromised public key; a `not_after` date alone is not enough.
- Removing a key invalidates old codes too, once caches refresh. Offline pins
  need their own update/revocation policy.
- General scanners cannot detect signature removal without an expected-signer
  policy. A required signature must fail closed, not silently downgrade.
- Automatic online discovery reveals a lookup to the signing domain and may
  target private network addresses. The local scanner demo is offline by default; online
  server deployments need the protections in [SCANNERS.md](SCANNERS.md).
- This reference reader and tests are not an independent security audit, and
  lab image decoding is not a guarantee about every phone camera.

The benefit is deliberately narrow: **keep the familiar QR instruction, add
verifiable origin and integrity, and let the application decide whom to trust**.
