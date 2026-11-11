"""Generate the QRSig project icon (docs/icon.svg).

A stylised QR code with a verification seal: the finder patterns and data
modules stand for the code, the check-marked seal for its signature.
"""

import random
from pathlib import Path

N = 21
CELL = 20
MARGIN = 56
SIZE = N * CELL + 2 * MARGIN

BACKGROUND = '#0f172a'
INK = '#f8fafc'
SEAL = '#22c55e'

SEAL_CENTER = 15.8
SEAL_RADIUS = 4.8
MODULE_GAP = 2


def px(cell):
    return MARGIN + cell * CELL


def in_finder_zone(row, col):
    near_top = row < 8
    near_left = col < 8
    return (near_top and near_left) or (near_top and col >= N - 8) or (row >= N - 8 and near_left)


def in_seal_zone(row, col):
    dr = row + 0.5 - SEAL_CENTER
    dc = col + 0.5 - SEAL_CENTER
    return dr * dr + dc * dc < (SEAL_RADIUS + 0.9) ** 2


def finder(row, col):
    x, y = px(col), px(row)
    return [
        f"<rect x='{x}' y='{y}' width='{7 * CELL}' height='{7 * CELL}' rx='{1.6 * CELL:g}' fill='{INK}'/>",
        f"<rect x='{x + CELL}' y='{y + CELL}' width='{5 * CELL}' height='{5 * CELL}' rx='{CELL}' fill='{BACKGROUND}'/>",
        f"<rect x='{x + 2 * CELL}' y='{y + 2 * CELL}' width='{3 * CELL}' height='{3 * CELL}' rx='{0.6 * CELL:g}' fill='{INK}'/>",
    ]


def seal():
    cx = cy = px(SEAL_CENTER)
    radius = SEAL_RADIUS * CELL
    s = radius * 0.5
    check = (
        f'M{cx - s:.1f} {cy + 0.05 * s:.1f} '
        f'L{cx - 0.25 * s:.1f} {cy + 0.75 * s:.1f} '
        f'L{cx + s:.1f} {cy - 0.6 * s:.1f}'
    )
    return [
        f"<circle cx='{cx:g}' cy='{cy:g}' r='{radius:g}' fill='{SEAL}'/>",
        f"<path d='{check}' fill='none' stroke='{BACKGROUND}' stroke-width='{radius * 0.2:.1f}' "
        "stroke-linecap='round' stroke-linejoin='round'/>",
    ]


def build_svg():
    rng = random.Random(20261111)
    parts = [
        f"<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 {SIZE} {SIZE}' width='{SIZE}' height='{SIZE}'>",
        f"<rect width='{SIZE}' height='{SIZE}' rx='{SIZE * 0.18:.0f}' fill='{BACKGROUND}'/>",
    ]
    for row, col in ((0, 0), (0, N - 7), (N - 7, 0)):
        parts += finder(row, col)
    size = CELL - 2 * MODULE_GAP
    for row in range(N):
        for col in range(N):
            if in_finder_zone(row, col) or in_seal_zone(row, col) or rng.random() < 0.5:
                continue
            parts.append(
                f"<rect x='{px(col) + MODULE_GAP}' y='{px(row) + MODULE_GAP}' "
                f"width='{size}' height='{size}' rx='3' fill='{INK}'/>"
            )
    parts += seal()
    parts.append('</svg>')
    return '\n'.join(parts) + '\n'


def main():
    target = Path(__file__).resolve().parent.parent / 'docs' / 'icon.svg'
    target.write_text(build_svg(), encoding='utf-8')
    print(target)


if __name__ == '__main__':
    main()
