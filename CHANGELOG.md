# Changelog

## Unreleased — QRSig v1 clarifications and JSON parsing fix

- Add the project website and interactive demo: [qrsig.org](https://qrsig.org/).
  Link it from the README, standard, guides and package project URLs.
- Explain verification using M (message), S (signature) and K (public key),
  with exact bytes and a runnable original/changed-content example.
- Distinguish a single Ed25519 boolean from the four QRSig outcomes and from
  application trust. Document skipped checks, key provenance and offline pins.
- Correct the scanner pseudocode: zero-valued validity bounds are not absent;
  check the future-time limit before key discovery.
- Resolve the UTF-8 segmentation ambiguity in favour of the existing reader:
  validate the concatenated payload, including sequences spanning byte segments.
  This is a normative clarification of the old per-segment wording, not a
  reader implementation change.
- Make existing key-document validation explicit: canonical raw-key encoding,
  integer or null bounds, whole-document rejection and bounded document size.
- Clarify exact signed bytes, domain syntax, fetch failure classifications and
  raw signature size versus its textual display.
- Add conformance tests for the clarified behavior and documentation examples.
- Reject non-JSON `NaN`, `Infinity` and `-Infinity` constants anywhere in a
  key document, including unknown members. Python previously accepted these;
  this is a parser hardening change aligning it with the JSON requirement.

The v1 block layout, context string, Ed25519 algorithm, key-discovery URL and
`vectors.json` are unchanged. Except for the explicit malformed-JSON rejection above,
these clarifications describe existing reference implementation behavior.
They do not introduce a new wire version or publish a package to PyPI.

## 0.1.0 — Initial draft reference implementation

- QRSig v1 specification, Python encoder/reader/verifier and CLI.
- Deterministic vectors, signed/unsigned sample images and local scanner demo.
- Offline pins, strict segment/key parsing and bounded HTTPS key discovery.
