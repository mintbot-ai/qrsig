"""qrsig: make keys, sign QR codes, check them.

    qrsig keygen -o key.json                      # prints what to publish at /.well-known/qrsig.json
    qrsig sign 'bitcoin:bc1q...' --domain pay.example.com --key key.json -o code.png
    qrsig verify code.png                         # fetches the signer's keys over HTTPS
    qrsig verify code.png --pin pay.example.com=qrsig.json    # or checks against a document you hold
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
from pathlib import Path

from . import format as fmt
from . import keys, qr


def _keygen(args) -> int:
    private, public = keys.generate()
    fd = os.open(args.out, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as fh:
        json.dump({"private_key": private, "public_key": public}, fh, indent=2)
        fh.write("\n")
    print(f"private key written to {args.out} (keep it secret)", file=sys.stderr)
    print(f"publish this at https://<your domain>{keys.WELL_KNOWN}:", file=sys.stderr)
    print(keys.document([public]), end="")
    return 0


def _sign(args) -> int:
    document = json.loads(Path(args.key).read_text(encoding="utf-8"))
    if not isinstance(document, dict) or not isinstance(document.get("private_key"), str):
        raise ValueError("key file needs a 'private_key' string")
    private = document["private_key"]
    code = qr.signed(args.text, args.domain, keys.private_key(private), ec=args.ec)
    code.make_image().save(args.out)
    print(f"{args.out}: {code.modules_count}x{code.modules_count} modules, signed by {args.domain}")
    return 0


def describe(result: dict) -> str:
    when = ""
    if result.get("issued_at") is not None:
        when = time.strftime(" on %Y-%m-%d %H:%M UTC", time.gmtime(result["issued_at"]))
    return {
        fmt.VERIFIED: f"verified: signed by {result['domain']}{when}",
        fmt.INVALID: f"INVALID: claims to be signed by {result['domain']}, but is not ({result['reason']})",
        fmt.UNVERIFIABLE: f"not checked: claims to be signed by {result['domain']} ({result['reason']})",
        fmt.UNSIGNED: "unsigned",
    }[result["status"]]


def _verify(args) -> int:
    resolver = keys.Resolver(offline=args.offline)
    for item in args.pin:
        domain, _, path = item.partition("=")
        if not fmt.is_domain(domain) or not path:
            raise ValueError("--pin must be DOMAIN=FILE with a valid QRSig domain")
        resolver.pin(domain, Path(path).read_bytes())
    result = qr.check(args.image, resolver)
    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print(f"payload:   {result['payload']}")
        print(f"signature: {describe(result)}")
    return 0 if result["status"] == fmt.VERIFIED else 1


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="qrsig", description="Signed QR codes (QRSig v1).")
    sub = parser.add_subparsers(dest="command", required=True)
    k = sub.add_parser("keygen", help="make a signing key")
    k.add_argument("-o", "--out", default="qrsig-key.json")
    k.set_defaults(run=_keygen)
    s = sub.add_parser("sign", help="make a signed QR code")
    s.add_argument("text")
    s.add_argument("--domain", required=True)
    s.add_argument("--key", default="qrsig-key.json")
    s.add_argument("-o", "--out", required=True)
    s.add_argument("--ec", default="M", choices=["L", "M", "Q", "H"])
    s.set_defaults(run=_sign)
    v = sub.add_parser("verify", help="read a QR code from a picture and check its signature")
    v.add_argument("image")
    v.add_argument("--pin", action="append", default=[], metavar="DOMAIN=FILE",
                   help="use this key document for the domain instead of fetching it")
    v.add_argument("--json", action="store_true")
    v.add_argument("--offline", action="store_true", help="never fetch keys; use pinned documents only")
    v.set_defaults(run=_verify)
    args = parser.parse_args(argv)
    try:
        return args.run(args)
    except (OSError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
