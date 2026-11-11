"""QRSig v1 in QR codes: hiding the block in the padding and reading it back
(SPEC.md, sections 2 and 3; docs/SCANNERS.md walks through the reading side).

Writing needs ``qrcode``; reading a picture needs ``zxing-cpp`` (finds the
code) and ``reedsolo`` (repairs damaged codewords).
"""
from __future__ import annotations

import time
from dataclasses import dataclass

from . import format as fmt

_ALPHANUMERIC = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:"
_NUMERIC, _ALNUM, _BYTE, _ECI = 1, 2, 4, 7
_CELL = 12  # pixels a module is sampled at, once the code is straightened


def _levels() -> dict:
    from qrcode import constants
    return {"L": constants.ERROR_CORRECT_L, "M": constants.ERROR_CORRECT_M,
            "Q": constants.ERROR_CORRECT_Q, "H": constants.ERROR_CORRECT_H}


# -- writing ------------------------------------------------------------------

def make(payload: str, block: bytes = b"", *, ec: str = "M", box_size: int = 10, border: int = 4):
    """A QR code of *payload* with *block* at the start of its padding: a
    ``qrcode.QRCode``; ``.make_image()`` draws it. The data is the library's
    own encoding (numeric, alphanumeric and UTF-8 byte segments), and the
    code is the smallest version that holds both."""
    import qrcode
    from qrcode import base, util

    level = _levels()[ec]
    code = qrcode.QRCode(error_correction=level, box_size=box_size, border=border)
    code.add_data(payload)
    if not block:
        code.make(fit=True)
        return code
    for version in range(1, 41):
        buffer = util.BitBuffer()
        for chunk in code.data_list:
            buffer.put(chunk.mode, 4)
            buffer.put(len(chunk), util.length_in_bits(chunk.mode, version))
            chunk.write(buffer)
        blocks = base.rs_blocks(version, level)
        limit = sum(b.data_count for b in blocks) * 8
        used = -(-(len(buffer) + 4) // 8) * 8  # the terminator, then up to a whole codeword
        if limit - used >= len(block) * 8:
            break
    else:
        raise ValueError("no QR version holds this payload with its signature")
    buffer.put(0, 4)                      # the terminator: every reader stops here
    while len(buffer) % 8:
        buffer.put_bit(False)
    for byte in block:                    # the block, in place of the first pad codewords
        buffer.put(byte, 8)
    pad = 0
    while len(buffer) < limit:            # the rest is the standard padding
        buffer.put((0xEC, 0x11)[pad % 2], 8)
        pad += 1
    code.version = version
    code.data_cache = util.create_bytes(buffer, blocks)
    code.make(fit=False)
    return code


def signed(payload: str, domain: str, private_key, *, issued_at: float | None = None, **options):
    """A QR code of *payload* signed by *domain*'s *private_key*."""
    block = fmt.sign(payload.encode("utf-8"), domain, private_key, issued_at=issued_at)
    return make(payload, block, **options)


# -- reading ------------------------------------------------------------------

@dataclass(frozen=True)
class Scan:
    payload: bytes     # what the code says, as the bytes that were signed
    padding: bytes     # what follows the terminator
    version: int
    ec: str

    @property
    def text(self) -> str:
        return self.payload.decode("utf-8", "replace")


def split(data: bytes, version: int) -> tuple[bytes, bytes]:
    """(payload, padding) of a code's data codewords (after error correction).
    ``ValueError`` for a code QRSig does not cover (Kanji, FNC1, structured
    append): such a code is simply unsigned."""
    from qrcode import util

    bits = int.from_bytes(data, "big")
    total = len(data) * 8
    pos = 0

    def take(n: int) -> int:
        nonlocal pos
        if pos + n > total:
            raise ValueError("truncated")
        pos += n
        return (bits >> (total - pos)) & ((1 << n) - 1)

    payload = bytearray()
    while total - pos >= 4:
        mode = take(4)
        if mode == 0:
            return bytes(payload), data[(pos + 7) // 8:]
        if mode == _ECI:  # a designator of one to three bytes; the data that follows says the rest
            first = take(8)
            take(8 if first & 0xC0 == 0x80 else 16 if first & 0xE0 == 0xC0 else 0)
            continue
        if mode not in (_NUMERIC, _ALNUM, _BYTE):
            raise ValueError("unsupported mode")
        count = take(util.length_in_bits(mode, version))
        if mode == _NUMERIC:
            for _ in range(count // 3):
                payload += b"%03d" % take(10)
            if count % 3 == 2:
                payload += b"%02d" % take(7)
            elif count % 3 == 1:
                payload += b"%d" % take(4)
        elif mode == _ALNUM:
            for _ in range(count // 2):
                pair = take(11)
                payload += (_ALPHANUMERIC[pair // 45] + _ALPHANUMERIC[pair % 45]).encode()
            if count % 2:
                payload += _ALPHANUMERIC[take(6)].encode()
        else:
            for _ in range(count):
                payload.append(take(8))
    return bytes(payload), b""  # the data fills the code: no terminator, no padding


def _function_patterns(version: int, level: int, mask: int) -> list[list]:
    """The modules a code of this version fixes; None where data goes."""
    import qrcode

    code = qrcode.QRCode(version=version, error_correction=level)
    size = version * 4 + 17
    code.modules_count = size
    code.modules = [[None] * size for _ in range(size)]
    code.setup_position_probe_pattern(0, 0)
    code.setup_position_probe_pattern(size - 7, 0)
    code.setup_position_probe_pattern(0, size - 7)
    code.setup_position_adjust_pattern()
    code.setup_timing_pattern()
    code.setup_type_info(False, mask)
    if version >= 7:
        code.setup_type_number(False)
    return code.modules


def data_codewords(matrix: list[list[bool]], version: int, ec: str, mask: int) -> bytes:
    """The data codewords of a module matrix (True = dark), damage repaired
    by the code's own error correction. ``ValueError`` when it cannot be."""
    from qrcode import base, util
    from reedsolo import ReedSolomonError, RSCodec

    level = _levels()[ec]
    size = version * 4 + 17
    fixed = _function_patterns(version, level, mask)
    masked = util.mask_func(mask)
    raw, acc, count = bytearray(), 0, 0
    row, step = size - 1, -1
    for col in range(size - 1, 0, -2):    # two columns at a time, right to left, zigzag
        if col <= 6:
            col -= 1                      # the vertical timing column is skipped
        while True:
            for c in (col, col - 1):
                if fixed[row][c] is None:
                    acc = (acc << 1) | int(bool(matrix[row][c]) != bool(masked(row, c)))
                    count += 1
                    if count == 8:
                        raw.append(acc)
                        acc, count = 0, 0
            row += step
            if row < 0 or row >= size:
                row -= step
                step = -step
                break
    blocks = base.rs_blocks(version, level)
    data = [bytearray() for _ in blocks]
    ecc = [bytearray() for _ in blocks]
    stream = iter(raw)
    for i in range(max(b.data_count for b in blocks)):          # codewords are interleaved
        for n, block in enumerate(blocks):
            if i < block.data_count:
                data[n].append(next(stream))
    for i in range(max(b.total_count - b.data_count for b in blocks)):
        for n, block in enumerate(blocks):
            if i < block.total_count - block.data_count:
                ecc[n].append(next(stream))
    out = bytearray()
    for n in range(len(blocks)):
        try:
            out += RSCodec(len(ecc[n])).decode(data[n] + ecc[n])[0]
        except ReedSolomonError:
            raise ValueError("too damaged") from None
    return bytes(out)


def _straighten(image, position, size: int) -> list[list[bool]]:
    from PIL import Image, ImageOps

    side = size * _CELL
    quad = (position.top_left.x, position.top_left.y, position.bottom_left.x, position.bottom_left.y,
            position.bottom_right.x, position.bottom_right.y, position.top_right.x, position.top_right.y)
    flat = ImageOps.autocontrast(image.convert("L")).transform(
        (side, side), Image.Transform.QUAD, quad, Image.Resampling.BILINEAR)
    px = flat.load()
    lo, hi = _CELL // 2 - 1, _CELL // 2 + 2

    def dark(row: int, col: int) -> bool:
        total = sum(px[col * _CELL + x, row * _CELL + y] for y in range(lo, hi) for x in range(lo, hi))
        return total < 128 * (hi - lo) ** 2

    matrix = [[dark(row, col) for col in range(size)] for row in range(size)]
    if not matrix[3][3]:  # the heart of a finder pattern is dark: this code is light on dark
        matrix = [[not module for module in row] for row in matrix]
    return matrix


def read(image) -> Scan:
    """The first QR code in *image* (a path or a PIL image). ``ValueError``
    when there is none, it is too damaged, or QRSig does not cover it."""
    import zxingcpp
    from PIL import Image

    if hasattr(image, "get_image"):       # what qrcode's make_image() returns
        image = image.get_image()
    if not isinstance(image, Image.Image):
        image = Image.open(image)
    image = image.convert("RGB")
    found = [r for r in zxingcpp.read_barcodes(image) if "Version" in r.extra and "DataMask" in r.extra]
    if not found:
        raise ValueError("no QR code found")
    code = found[0]
    version, ec, mask = int(code.extra["Version"]), str(code.extra["ECLevel"]), int(code.extra["DataMask"])
    matrix = _straighten(image, code.position, version * 4 + 17)
    payload, padding = split(data_codewords(matrix, version, ec, mask), version)
    return Scan(payload, padding, version, ec)


def check(image, keys_for, *, now: float | None = None) -> dict:
    """What the QR code in *image* says and who signed it."""
    scan = read(image)
    result = fmt.verify(scan.payload, scan.padding, keys_for, now=time.time() if now is None else now)
    return {"payload": scan.text, "modules": scan.version * 4 + 17, "status": result.status,
            "domain": result.domain, "issued_at": result.issued_at, "reason": result.reason}
