"""Malformed segments must not be turned into a different signed payload."""
import pytest
from qrcode.util import BitBuffer
from qrsig import qr


@pytest.mark.parametrize('mode,count,count_bits,value,value_bits', [
    (1, 3, 10, 1000, 10), (1, 2, 10, 100, 7), (1, 1, 10, 10, 4),
    (2, 2, 9, 2025, 11), (2, 1, 9, 45, 6),
])
def test_out_of_range_segment_is_rejected(mode, count, count_bits, value, value_bits):
    buf = BitBuffer()
    for n, width in [(mode, 4), (count, count_bits), (value, value_bits), (0, 4)]:
        buf.put(n, width)
    with pytest.raises(ValueError, match='segment'):
        qr.split(bytes(buf.buffer), 1)


def test_invalid_utf8_is_not_presented_as_verified_replacement_text():
    buf = BitBuffer()
    for n, width in [(4, 4), (1, 8), (255, 8), (0, 4)]:
        buf.put(n, width)
    with pytest.raises(ValueError):
        qr.split(bytes(buf.buffer), 1)


@pytest.mark.parametrize('eci', [3, 0xe0])
def test_non_utf8_or_invalid_eci_is_not_signed_text(eci):
    buf = BitBuffer()
    for n, width in [(7, 4), (eci, 8), (4, 4), (1, 8), (65, 8), (0, 4)]:
        buf.put(n, width)
    with pytest.raises(ValueError, match='ECI'):
        qr.split(bytes(buf.buffer), 1)


def test_utf8_eci_is_supported():
    buf = BitBuffer()
    for n, width in [(7, 4), (26, 8), (4, 4), (1, 8), (65, 8), (0, 4)]:
        buf.put(n, width)
    assert qr.split(bytes(buf.buffer), 1) == (b'A', b'')
