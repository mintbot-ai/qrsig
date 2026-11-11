# QRSig: signed QR codes

A QR code that says who made it.

The issuer signs the code's content with a key its domain publishes. A
scanner that knows QRSig shows **"Signed by pay.example.com"**; every other
tested ordinary readers return the same content, because the signature is not
in the content. It rides after the terminator, where readers normally stop.
This is a draft padding extension, not a claim of strict ISO/IEC 18004
conformance or compatibility with every scanner.

```
what a phone reads     bitcoin:bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh?amount=0.00123456
what QRSig adds        signed by pay.example.com on 2026-11-10, Ed25519, 87 hidden bytes
```

- **[SPEC.md](SPEC.md)**: the standard. One block of bytes, one JSON file on
  your domain, one verification procedure.
- **[docs/SCANNERS.md](docs/SCANNERS.md)**: how a QR scanner reads and
  checks the signature.
- **`qrsig/`**: the reference implementation (Python).
- **`examples/`**: a demo scanner and sample codes.
- **[vectors.json](vectors.json)**: test vectors.
- **[docs/EXPLAINED.md](docs/EXPLAINED.md)**: a byte-by-byte example, use cases
  and what a signature does not prove.

Status: draft 1. The format may still change before 1.0.

## Why

A QR code is an anonymous instruction: open this link, pay this address. A
sticker over a parking meter's code, a swapped payment code on an invoice or
a fake login code all work because nothing in the code says where it came
from. QRSig gives a scanner or a wallet something to check before acting:

- a wallet can show which service generated a payment address, and warn when
  a code that claims to be from that service is not;
- a login or ticket app can refuse codes its own domain did not sign;
- a printed code stays verifiable for as long as the issuer keeps its key
  published.

What it does not do: stop a signed code from being copied, or tell you
whether the signing domain deserves trust. It authenticates a domain-key
claim, not a person, a safe destination, payment completion or a physical object.
See the security section of the spec.

## How it works

```
 issuer                                   scanner
 ------                                   -------
 content ──┐                              read code as usual ──► content (shown at once)
           ├─ Ed25519 sign ─► block       take the bytes after the terminator ──► block
 domain ───┘        │                     GET https://<domain>/.well-known/qrsig.json
                    ▼                     verify block against the domain's keys
 QR code: | content | terminator | block | padding |        ──► "Signed by <domain>"
```

1. The domain publishes its public key at `/.well-known/qrsig.json`.
2. The block (magic, version, time, domain, signature: 72 bytes plus the
   domain name) replaces the first padding bytes of the code.
3. A scanner reads the block, fetches the domain's keys over HTTPS and
   reports one of four outcomes: `verified`, `invalid`, `unverifiable`,
   `unsigned`.

## Try it

```sh
pip install -e '.[read]'          # from a checkout; Python 3.10+

# 1. Make a key. The JSON it prints goes to https://<your domain>/.well-known/qrsig.json
qrsig keygen -o qrsig-key.json > qrsig.json

# 2. Sign a code
qrsig sign 'bitcoin:bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh?amount=0.001' \
      --domain pay.example.com --key qrsig-key.json -o code.png

# 3. Check it without network access. Omit --offline and --pin for HTTPS discovery.
qrsig verify code.png --offline --pin pay.example.com=qrsig.json
# payload:   bitcoin:bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh?amount=0.001
# signature: verified: signed by pay.example.com on <your signing time in UTC>
```

The repository carries a ready pair, signed with the test key of the
vectors:

```sh
qrsig verify examples/signed-bitcoin.png --pin pay.example.com=examples/pay.example.com.qrsig.json
qrsig verify examples/unsigned-bitcoin.png        # same content, unsigned
```

An ordinary compatible scanner shows only the Bitcoin URI, not the signature.
The sample key is public test material: never use it in production and do not
pay the example address. A pin checks the supplied key, not live domain control.
`--pin` alone does not disable fetching for other domains; `--offline` does.
Exit codes: 0 = verified, 1 = another verification outcome, 2 = input/read error.

### The demo scanner

```sh
python examples/scanner_web.py --pin pay.example.com=examples/pay.example.com.qrsig.json
# open http://127.0.0.1:8765, choose or photograph a code
```

It shows the content and, under it, "Signed by ...", a warning, or nothing,
as section 7 of the spec asks of a scanner. It is offline by default: use
`--pin` for trusted key documents. `--online` explicitly enables requests to
signer-controlled hosts. This is a localhost demo, not a hardened public
upload service; see the deployment warnings in [docs/SCANNERS.md](docs/SCANNERS.md).

### In code

```python
from qrsig import keys, qr

private, public = keys.generate()
code = qr.signed("https://example.com/invoice/8c1f", "example.com", keys.private_key(private))
code.make_image().save("invoice.png")

resolver = keys.Resolver(offline=True)               # pins only; no network
resolver.pin("example.com", keys.document([public]).encode())   # here: the document, handed over
result = qr.check("invoice.png", resolver)
result["status"], result["domain"]                   # "verified", "example.com"
```

## In use: mintbot

QRSig grew out of [mintbot](https://mintbot.ai), which signs the QR codes it
shows. The purpose there is the one in the title: to be able to tell whether
a payment or sign-in code was really generated by mintbot.

- **Crypto payments.** The Bitcoin and Monero payment codes on mintbot's
  checkout pages, and the panel links its Telegram bot sends, have a QRSig 1
  implementation in mintbot: signed under `mintbot.ai`, with key publication at
  `https://mintbot.ai/.well-known/qrsig.json`. The code that does it is small:
  one function that builds the block, one route that serves the document.
  This describes the integration code, not a guarantee that every live
  deployment has updated or currently publishes the document.
  mintbot's implementation is independent of this repository's and is tested
  against `vectors.json`; `qrsig verify` reads mintbot's payment codes as
  "verified: signed by mintbot.ai".
- **Agent panels.** The sign-in, device-link and authenticator codes that a
  customer's own agent server draws are signed by that server's key in an
  earlier, mintbot-internal format (same place in the padding, a key id
  instead of a domain). They move to QRSig once each agent host publishes its
  own key document.

Two things mintbot's rollout taught, both now in the spec:

- **The signature costs size.** About 80 bytes makes a code four to seven
  versions larger. mintbot enlarged every displayed code by the same factor
  (a payment code from 160 to 216 px), which brought the simulated scan
  margin back to what it was.
- **Styling costs more than signing.** With plain square modules, ZXing and
  ZBar read signed codes as reliably as unsigned ones. Round dots and a logo
  in the middle cost ZBar 5 to 17% of reads in mintbot's measurements,
  signed or not. If a code must scan everywhere, draw it plain.

## For scanner and wallet authors

The change in a decoder is small: keep the bytes after the terminator instead
of discarding them. [docs/SCANNERS.md](docs/SCANNERS.md) walks through it,
with pseudo-code for parsing, fetching, verifying and displaying, and
`qrsig/qr.py` is a complete reader to compare against.

## Tests

```sh
pip install -e '.[test]'      # pyzbar also needs the zbar library (libzbar0)
python -m pytest
python tools/make_vectors.py  # regenerates vectors.json; it must not change
```

## Licence

The code is under the MIT licence (see [LICENSE](LICENSE)). The
specification may be implemented by anyone, for any purpose, without
permission or fee.
