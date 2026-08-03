#!/usr/bin/env python3
"""Frostline / WoS calibration measurer.

Reads screenshots of the calibration messages (one per strings/*.txt,
photographed inside WoS chat) and derives the game's real advance width
for every calibrated character:

    advance_px = (ink_width(2N reps) - ink_width(N reps)) / N

The two-line difference cancels the end-marker width and every side
bearing, so the number is the true advance. Everything is normalized to
U+2588 (full block) and also reported in px so the reference is explicit.

Usage:
    python3 measure.py SHOTS_DIR [--spec spec.json] [--out wos-metrics.json]

SHOTS_DIR must contain one image per message named after the message id,
e.g. c1_blocks.png (any of .png/.jpg). Requires Pillow.
"""
import argparse
import json
import os
import sys

from PIL import Image

# WoS chat colors, sampled from real Galaxy S24 Ultra screenshots (JPEG).
# Bubble: light green ~(198,243,196). Ink: dark green ~(16,100,16).
BUBBLE = (198, 243, 196)
BUBBLE_TOL = (30, 22, 32)
# Thresholds are wide enough to catch anti-aliased thin strokes (e.g. the
# 2px stem of U+2502); the green-dominance test still excludes blends of
# the blue chat background, which are blue-dominant.
INK_MAX_R, INK_MAX_G, INK_MAX_B = 140, 190, 140
INK_GREEN_LEAD = 15  # ink must be green-dominant by this much

MIN_BUBBLE_ROW_FRAC = 0.22   # a row is "bubble" if >=22% of sampled px match
MIN_BUBBLE_HEIGHT = 60
LINE_GAP_ROWS = 4            # blank rows separating two text lines


def is_bubble(px):
    r, g, b = px
    return (abs(r - BUBBLE[0]) < BUBBLE_TOL[0]
            and abs(g - BUBBLE[1]) < BUBBLE_TOL[1]
            and abs(b - BUBBLE[2]) < BUBBLE_TOL[2])


def is_ink(px):
    r, g, b = px
    return (r < INK_MAX_R and g < INK_MAX_G and b < INK_MAX_B
            and g > r + INK_GREEN_LEAD and g > b + INK_GREEN_LEAD)


def bubble_bands(im):
    """Y-ranges of chat bubbles (light-green horizontal bands).

    Rows are counted as bubble if bubble-color OR ink pixels clear the
    threshold: a row of wide art ink is still inside the bubble, while
    the dark background between two bubbles has neither color."""
    w, h = im.size
    pix = im.load()
    bands, cur = [], None
    step = max(1, w // 300)
    need = (w // step) * MIN_BUBBLE_ROW_FRAC
    for y in range(h):
        n = sum(1 for x in range(0, w, step)
                if is_bubble(pix[x, y]) or is_ink(pix[x, y]))
        if n >= need:
            cur = [y, y] if cur is None else [cur[0], y]
        else:
            if cur:
                bands.append(tuple(cur))
            cur = None
    if cur:
        bands.append(tuple(cur))
    # Merge bands split by detection glitches: real gaps between two chat
    # bubbles are 80+ rows; anything closer is the same bubble. Filter by
    # height only after merging so small fragments rejoin their bubble.
    merged = []
    for b in bands:
        if merged and b[0] - merged[-1][1] < 40:
            merged[-1] = (merged[-1][0], b[1])
        else:
            merged.append(b)
    return [b for b in merged if b[1] - b[0] >= MIN_BUBBLE_HEIGHT]


def ink_lines(im, y0, y1):
    """Detect text lines (ink bands) inside a bubble; return per-line
    (ymin, ymax, xmin, xmax). Calibration strings put an ink-free spacer
    line between rulers, so simple gap segmentation is reliable."""
    w, _ = im.size
    pix = im.load()
    lines, cur, gap = [], None, 0
    for y in range(y0, y1 + 1):
        xs = [x for x in range(w) if is_ink(pix[x, y])]
        if xs:
            lo, hi = min(xs), max(xs)
            if cur is None:
                cur = [y, y, lo, hi]
            else:
                cur[1] = y
                cur[2] = min(cur[2], lo)
                cur[3] = max(cur[3], hi)
            gap = 0
        elif cur is not None:
            gap += 1
            if gap >= LINE_GAP_ROWS:
                lines.append(tuple(cur))
                cur = None
    if cur is not None:
        lines.append(tuple(cur))
    return lines


def find_shot(shots_dir, msg_id):
    for ext in ('.png', '.jpg', '.jpeg', '.webp'):
        p = os.path.join(shots_dir, msg_id + ext)
        if os.path.exists(p):
            return p
    return None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('shots')
    here = os.path.dirname(os.path.abspath(__file__))
    ap.add_argument('--spec', default=os.path.join(here, 'spec.json'))
    ap.add_argument('--out', default='wos-metrics.json')
    args = ap.parse_args()

    spec = json.load(open(args.spec, encoding='utf-8'))
    results = {}   # char -> {'px': advance_px}
    problems = []

    for msg in spec['messages']:
        shot = find_shot(args.shots, msg['id'])
        if not shot:
            problems.append(f"missing screenshot for {msg['id']}")
            continue
        im = Image.open(shot).convert('RGB')
        bands = bubble_bands(im)
        if not bands:
            problems.append(f"{msg['id']}: no chat bubble found")
            continue
        # The calibration message is the newest = bottom-most bubble.
        y0, y1 = bands[-1]
        lines = ink_lines(im, y0, y1)
        expected = 1 + len(msg['rulers'])          # label + one line per ruler
        if len(lines) != expected:
            problems.append(
                f"{msg['id']}: found {len(lines)} ink lines, expected "
                f"{expected} — check the screenshot shows the whole message")
            if len(lines) < expected:
                continue
            lines = lines[-expected:]              # newest content wins
        rulers = lines[1:]                          # drop the label line
        widths = [x1 - x0 + 1 for (_, _, x0, x1) in rulers]
        # rulers come in (N, 2N) pairs per char, in spec order
        for i in range(0, len(msg['rulers']), 2):
            a, b = msg['rulers'][i], msg['rulers'][i + 1]
            n = a['reps']
            adv = (widths[i + 1] - widths[i]) / n
            if adv <= 0:
                problems.append(
                    f"{msg['id']}: {a['char']} measured non-positive advance "
                    f"({widths[i]}px -> {widths[i + 1]}px) — lines likely "
                    f"merged or mis-detected; retake this screenshot")
                continue
            results[a['char']] = {
                'label': a['label'], 'px': round(adv, 2),
                'w_n_px': widths[i], 'w_2n_px': widths[i + 1],
            }

    ref = results.get('U+2588', {}).get('px')
    for c, r in results.items():
        r['em'] = round(r['px'] / ref, 4) if ref else None

    out = {'reference': 'U+2588 full block = 1.0',
           'ref_px': ref, 'chars': results, 'problems': problems}
    json.dump(out, open(args.out, 'w', encoding='utf-8'),
              indent=1, ensure_ascii=False)

    print(f"{'char':<9} {'advance px':>11} {'vs █':>7}  label")
    for c, r in results.items():
        em = f"{r['em']:.3f}" if r.get('em') is not None else '?'
        print(f"{c:<9} {r['px']:>11.2f} {em:>7}  {r['label']}")
    if problems:
        print('\nPROBLEMS:', file=sys.stderr)
        for p in problems:
            print('  -', p, file=sys.stderr)
    print(f"\nwrote {args.out}")


if __name__ == '__main__':
    main()
