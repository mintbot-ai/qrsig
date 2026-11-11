# QRSig: signed QR codes

A QR code that says who made it. **One code. Two layers.**

The ordinary layer is still a URL, payment URI or text. QRSig adds an
Ed25519 signature after the QR terminator, where ordinary readers stop.
A QRSig-aware scanner also checks the issuer's domain and shows
**“Signed by pay.example.com”**.

**[Website & interactive demo](https://qrsig.org/)** ·
[Specification](SPEC.md) · [Inside a signed QR](docs/EXPLAINED.md) ·
[Build a scanner](docs/SCANNERS.md)

Status: **draft 1**. This is a padding extension, not a claim of strict
ISO/IEC 18004 conformance or compatibility with every scanner. The format
may change before 1.0. See [CHANGELOG.md](CHANGELOG.md) for revisions.

## Start with the demo

On [qrsig.org](https://qrsig.org/), follow **QR code → Address + signature →
Verify**. Open the compact M, S and K panels to inspect the bytes and key
source. Switch to a changed address: the same signature no longer matches.
“Validate signature” checks the currently selected address; switching back
restores the original.

The page is an interactive explanation, not a general-purpose image scanner:
it checks bytes extracted from the example QR ahead of time. To decode and
verify the actual PNG with domain-key discovery, use the CLI below.
Bitcoin is just the example; QRSig can sign other UTF-8 content too.

## Three inputs. One signature check.

| Input | What it is | Where it comes from |
|---|---|---|
| **M — message** | `context || header || payload` | Fixed QRSig context plus bytes read from the QR |
| **S — signature** | 64 raw Ed25519 bytes | The QRSig block in the QR padding |
| **K — public key** | 32 raw Ed25519 bytes | The signing domain's HTTPS key document |

```text
M = ASCII("qrsig1\n") || header || payload
Ed25519.verify(K, S, M) → true or false
```

`||` means joining bytes, not adding numbers or inserting separators. The
header includes the domain and claimed issue time. The signature binds those
fields to the exact payload; it does not sign the image pixels.

The boolean above is one cryptographic check, not the whole protocol.
QRSig checks the block, time, key source and eligible keys, then reports:

| Outcome | Meaning |
|---|---|
| `verified` | An eligible key published by the named domain verifies the message |
| `invalid` | The claim fails: changed bytes, no matching/eligible published key, or an invalid time |
| `unverifiable` | The keys could not be obtained now; this is not success |
| `unsigned` | No supported, well-formed QRSig v1 block was found |

A valid signature does not prove Bitcoin-address ownership, a safe URL,
payment completion or that a copied code is original. Applications still
need to know which domains they trust. Details: [security considerations](SPEC.md#9-security-considerations).

## Try it locally

Python 3.10+ is required. Install **this repository**, not the unrelated
package with the same name on PyPI:

```sh
git clone https://github.com/mintbot-ai/qrsig.git
cd qrsig
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -e '.[read]'
```

### Check the published example

```sh
curl -fSLo live-qrsig.png https://qrsig.org/demo/bitcoin-signed.png
qrsig verify live-qrsig.png
```

This decodes the image and fetches
`https://qrsig.org/.well-known/qrsig.json` over HTTPS. When the issuer's key is
available and matches, the result is `verified: signed by qrsig.org` followed
by its claimed signing time. This is a live check, not an offline fixture;
network availability and the issuer's current key document affect its result.
**Do not send money to the demonstration address.**

### Check the repository fixture, offline

```sh
qrsig verify examples/signed-bitcoin.png --offline --pin pay.example.com=examples/pay.example.com.qrsig.json
qrsig verify examples/unsigned-bitcoin.png --offline
```

These report `verified` and `unsigned`, respectively. The fixture uses a
public test key from [vectors.json](vectors.json); never use it in production.
A pin checks the supplied key, not live domain control. `--pin` alone does not
disable lookups for other domains; `--offline` does.

CLI exit codes: **0** = verified, **1** = another verification outcome,
**2** = input/read error. The unsigned example intentionally exits with 1.

### Sign your own code

```sh
qrsig keygen -o qrsig-key.json > qrsig.json
qrsig sign 'https://example.com/invoice/8c1f' \
      --domain example.com --key qrsig-key.json -o code.png
qrsig verify code.png --offline --pin example.com=qrsig.json
```

Use your own domain for real codes. Keep `qrsig-key.json` private. Publish only
`qrsig.json` at `https://<your-domain>/.well-known/qrsig.json`; then other
readers can verify without a pin. [Key publication and rotation](SPEC.md#5-the-key-document)
are part of the standard.

### Use the Python API

```python
from qrsig import keys, qr

private, public = keys.generate()
code = qr.signed("https://example.com/invoice/8c1f", "example.com", keys.private_key(private))
code.make_image().save("invoice.png")

resolver = keys.Resolver(offline=True)
resolver.pin("example.com", keys.document([public]).encode())
result = qr.check("invoice.png", resolver)
assert result["status"] == "verified"
assert result["domain"] == "example.com"
```

### Run the local scanner demo

```sh
python examples/scanner_web.py --pin pay.example.com=examples/pay.example.com.qrsig.json
# open http://127.0.0.1:8765, choose or photograph a code
```

Unlike the website illustration, this demo reads uploaded images. It is
offline by default. `--online` enables lookups to signer-controlled hosts;
it is not a hardened public upload service. Read the
[network deployment guidance](docs/SCANNERS.md#3-get-the-domains-keys) first.

## For implementers

- [SPEC.md](SPEC.md): block format, key document, verification and display rules.
- [docs/EXPLAINED.md](docs/EXPLAINED.md): bytes, a runnable true/false example,
  use cases and limitations.
- [docs/SCANNERS.md](docs/SCANNERS.md): corrected QR codewords → payload and
  padding → keys → verification → display.
- [`qrsig/`](qrsig/): Python reference implementation.
- [vectors.json](vectors.json) and [`examples/`](examples/): deterministic
  fixtures, sample pictures and local scanner.

Keep the payload and padding from the same corrected QR stream. A text-only
scanner API is not enough. Display the signing domain, not just a green tick.

## Size and origins

The hidden block costs **72 bytes + the domain length**, including its
64-byte signature. Hex/base64 in a UI is only a display format; the QR stores
raw signature bytes. Changing the display encoding does not shrink the QR.
See the [measured size table](SPEC.md#8-notes-for-issuers).

QRSig grew out of [mintbot](https://mintbot.ai). Its payment-code integration
uses the QRSig 1 format; earlier agent-generated codes used a different,
internal format. An integration's source code does not establish which
version is running on every live deployment. The public specification and
vectors here define interoperability.

## Tests

```sh
python -m pip install -e '.[test]'  # pyzbar also needs libzbar0
python -m pytest
python tools/make_vectors.py       # vectors.json must remain unchanged
```

## Licence

The code is under the MIT licence (see [LICENSE](LICENSE)). The specification
may be implemented by anyone, for any purpose, without permission or fee.
