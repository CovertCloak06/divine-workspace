#!/usr/bin/env python3
"""
Color Picker - Convert and display colors
Usage: color_picker.py [color]
"""

import re
import argparse
import random

CYAN = '\033[96m'
GREEN = '\033[92m'
YELLOW = '\033[93m'
RED = '\033[91m'
RESET = '\033[0m'
BOLD = '\033[1m'
DIM = '\033[2m'


# Named colors (CSS)
NAMED_COLORS = {
    'black': (0, 0, 0),
    'white': (255, 255, 255),
    'red': (255, 0, 0),
    'green': (0, 128, 0),
    'blue': (0, 0, 255),
    'yellow': (255, 255, 0),
    'cyan': (0, 255, 255),
    'magenta': (255, 0, 255),
    'orange': (255, 165, 0),
    'purple': (128, 0, 128),
    'pink': (255, 192, 203),
    'brown': (165, 42, 42),
    'gray': (128, 128, 128),
    'grey': (128, 128, 128),
    'lime': (0, 255, 0),
    'navy': (0, 0, 128),
    'teal': (0, 128, 128),
    'olive': (128, 128, 0),
    'maroon': (128, 0, 0),
    'silver': (192, 192, 192),
    'aqua': (0, 255, 255),
    'fuchsia': (255, 0, 255),
    'coral': (255, 127, 80),
    'salmon': (250, 128, 114),
    'gold': (255, 215, 0),
    'khaki': (240, 230, 140),
    'indigo': (75, 0, 130),
    'violet': (238, 130, 238),
    'turquoise': (64, 224, 208),
    'tomato': (255, 99, 71),
    'orchid': (218, 112, 214),
    'crimson': (220, 20, 60),
    'chocolate': (210, 105, 30),
    'sienna': (160, 82, 45),
}


def parse_color(color_str):
    """Parse color string to RGB tuple"""
    color_str = color_str.strip().lower()

    # Named color
    if color_str in NAMED_COLORS:
        return NAMED_COLORS[color_str]

    # Hex color: #RGB or #RRGGBB
    hex_match = re.match(r'^#?([0-9a-f]{3}|[0-9a-f]{6})$', color_str)
    if hex_match:
        hex_val = hex_match.group(1)
        if len(hex_val) == 3:
            r = int(hex_val[0] * 2, 16)
            g = int(hex_val[1] * 2, 16)
            b = int(hex_val[2] * 2, 16)
        else:
            r = int(hex_val[0:2], 16)
            g = int(hex_val[2:4], 16)
            b = int(hex_val[4:6], 16)
        return (r, g, b)

    # RGB: rgb(r, g, b)
    rgb_match = re.match(r'^rgb\s*\(\s*(\d+)\s*,\s*(\d+)\s*,\s*(\d+)\s*\)$', color_str)
    if rgb_match:
        r = min(255, int(rgb_match.group(1)))
        g = min(255, int(rgb_match.group(2)))
        b = min(255, int(rgb_match.group(3)))
        return (r, g, b)

    # Just three numbers: r g b or r,g,b
    num_match = re.match(r'^(\d+)[,\s]+(\d+)[,\s]+(\d+)$', color_str)
    if num_match:
        r = min(255, int(num_match.group(1)))
        g = min(255, int(num_match.group(2)))
        b = min(255, int(num_match.group(3)))
        return (r, g, b)

    return None


def rgb_to_hex(r, g, b):
    """Convert RGB to hex"""
    return f"#{r:02x}{g:02x}{b:02x}"


def rgb_to_hsl(r, g, b):
    """Convert RGB to HSL"""
    r, g, b = r / 255, g / 255, b / 255

    max_c = max(r, g, b)
    min_c = min(r, g, b)
    l = (max_c + min_c) / 2

    if max_c == min_c:
        h = s = 0
    else:
        d = max_c - min_c
        s = d / (2 - max_c - min_c) if l > 0.5 else d / (max_c + min_c)

        if max_c == r:
            h = ((g - b) / d + (6 if g < b else 0)) / 6
        elif max_c == g:
            h = ((b - r) / d + 2) / 6
        else:
            h = ((r - g) / d + 4) / 6

    return (int(h * 360), int(s * 100), int(l * 100))


def rgb_to_hsv(r, g, b):
    """Convert RGB to HSV"""
    r, g, b = r / 255, g / 255, b / 255

    max_c = max(r, g, b)
    min_c = min(r, g, b)
    d = max_c - min_c

    v = max_c
    s = 0 if max_c == 0 else d / max_c

    if max_c == min_c:
        h = 0
    elif max_c == r:
        h = ((g - b) / d + (6 if g < b else 0)) / 6
    elif max_c == g:
        h = ((b - r) / d + 2) / 6
    else:
        h = ((r - g) / d + 4) / 6

    return (int(h * 360), int(s * 100), int(v * 100))


def rgb_to_cmyk(r, g, b):
    """Convert RGB to CMYK"""
    if r == 0 and g == 0 and b == 0:
        return (0, 0, 0, 100)

    c = 1 - r / 255
    m = 1 - g / 255
    y = 1 - b / 255
    k = min(c, m, y)

    c = (c - k) / (1 - k) if k < 1 else 0
    m = (m - k) / (1 - k) if k < 1 else 0
    y = (y - k) / (1 - k) if k < 1 else 0

    return (int(c * 100), int(m * 100), int(y * 100), int(k * 100))


def get_luminance(r, g, b):
    """Calculate relative luminance"""
    r, g, b = r / 255, g / 255, b / 255

    def adjust(c):
        return c / 12.92 if c <= 0.03928 else ((c + 0.055) / 1.055) ** 2.4

    return 0.2126 * adjust(r) + 0.7152 * adjust(g) + 0.0722 * adjust(b)


def get_contrast_ratio(rgb1, rgb2):
    """Calculate contrast ratio between two colors"""
    l1 = get_luminance(*rgb1)
    l2 = get_luminance(*rgb2)
    lighter = max(l1, l2)
    darker = min(l1, l2)
    return (lighter + 0.05) / (darker + 0.05)


def display_color_block(r, g, b):
    """Display a color block using ANSI escape codes"""
    # Use true color (24-bit) escape codes
    return f"\033[48;2;{r};{g};{b}m       \033[0m"


def generate_palette(r, g, b):
    """Generate color palette"""
    h, s, l = rgb_to_hsl(r, g, b)

    palette = {
        'Original': (r, g, b),
    }

    # Complementary
    comp_h = (h + 180) % 360
    palette['Complementary'] = hsl_to_rgb(comp_h, s, l)

    # Lighter/Darker
    palette['Lighter'] = hsl_to_rgb(h, s, min(100, l + 20))
    palette['Darker'] = hsl_to_rgb(h, s, max(0, l - 20))

    # Analogous
    palette['Analogous 1'] = hsl_to_rgb((h + 30) % 360, s, l)
    palette['Analogous 2'] = hsl_to_rgb((h - 30) % 360, s, l)

    return palette


def hsl_to_rgb(h, s, l):
    """Convert HSL to RGB"""
    h, s, l = h / 360, s / 100, l / 100

    if s == 0:
        r = g = b = l
    else:
        def hue_to_rgb(p, q, t):
            if t < 0: t += 1
            if t > 1: t -= 1
            if t < 1/6: return p + (q - p) * 6 * t
            if t < 1/2: return q
            if t < 2/3: return p + (q - p) * (2/3 - t) * 6
            return p

        q = l * (1 + s) if l < 0.5 else l + s - l * s
        p = 2 * l - q

        r = hue_to_rgb(p, q, h + 1/3)
        g = hue_to_rgb(p, q, h)
        b = hue_to_rgb(p, q, h - 1/3)

    return (int(r * 255), int(g * 255), int(b * 255))


def main():
    parser = argparse.ArgumentParser(description='Color Picker')
    parser.add_argument('color', nargs='*', help='Color (hex, rgb, or name)')
    parser.add_argument('--random', '-r', action='store_true', help='Generate random color')
    parser.add_argument('--palette', '-p', action='store_true', help='Show color palette')
    parser.add_argument('--list', '-l', action='store_true', help='List named colors')
    args = parser.parse_args()

    print(f"\n{BOLD}{CYAN}╔════════════════════════════════════════════════════════════╗{RESET}")
    print(f"{BOLD}{CYAN}║              🎨 Color Picker                               ║{RESET}")
    print(f"{BOLD}{CYAN}╚════════════════════════════════════════════════════════════╝{RESET}\n")

    if args.list:
        print(f"  {BOLD}Named Colors:{RESET}")
        print(f"  {DIM}{'─' * 50}{RESET}\n")

        for name, (r, g, b) in sorted(NAMED_COLORS.items()):
            block = display_color_block(r, g, b)
            hex_val = rgb_to_hex(r, g, b)
            print(f"  {block} {name:<12} {DIM}{hex_val}{RESET}")

        print()
        return

    if args.random:
        r, g, b = random.randint(0, 255), random.randint(0, 255), random.randint(0, 255)
        color_str = f"#{r:02x}{g:02x}{b:02x}"
    elif args.color:
        color_str = ' '.join(args.color)
    else:
        color_str = input(f"  {CYAN}Enter color (hex, rgb, or name):{RESET} ").strip()

    if not color_str:
        print(f"  {RED}Color required{RESET}\n")
        return

    rgb = parse_color(color_str)
    if not rgb:
        print(f"  {RED}Could not parse color: {color_str}{RESET}")
        print(f"  {DIM}Try: #ff0000, rgb(255,0,0), red, or 255 0 0{RESET}\n")
        return

    r, g, b = rgb

    # Display color
    print(f"  {BOLD}Color:{RESET}")
    print(f"  {DIM}{'─' * 40}{RESET}\n")

    block = display_color_block(r, g, b)
    print(f"  {block}\n")

    # Color values
    print(f"  {CYAN}HEX:{RESET}  {GREEN}{rgb_to_hex(r, g, b).upper()}{RESET}")
    print(f"  {CYAN}RGB:{RESET}  rgb({r}, {g}, {b})")

    h, s, l = rgb_to_hsl(r, g, b)
    print(f"  {CYAN}HSL:{RESET}  hsl({h}, {s}%, {l}%)")

    h, s, v = rgb_to_hsv(r, g, b)
    print(f"  {CYAN}HSV:{RESET}  hsv({h}, {s}%, {v}%)")

    c, m, y, k = rgb_to_cmyk(r, g, b)
    print(f"  {CYAN}CMYK:{RESET} cmyk({c}%, {m}%, {y}%, {k}%)")

    # Contrast info
    white_contrast = get_contrast_ratio(rgb, (255, 255, 255))
    black_contrast = get_contrast_ratio(rgb, (0, 0, 0))

    print(f"\n  {BOLD}Contrast:{RESET}")
    print(f"  {CYAN}vs White:{RESET} {white_contrast:.2f}:1 {'✓' if white_contrast >= 4.5 else '✗'}")
    print(f"  {CYAN}vs Black:{RESET} {black_contrast:.2f}:1 {'✓' if black_contrast >= 4.5 else '✗'}")

    # Recommended text color
    text_color = "white" if black_contrast > white_contrast else "black"
    print(f"  {CYAN}Best text:{RESET} {text_color}")

    # Palette
    if args.palette:
        print(f"\n  {BOLD}Color Palette:{RESET}")
        print(f"  {DIM}{'─' * 40}{RESET}\n")

        palette = generate_palette(r, g, b)
        for name, (pr, pg, pb) in palette.items():
            block = display_color_block(pr, pg, pb)
            hex_val = rgb_to_hex(pr, pg, pb)
            print(f"  {block} {name:<15} {DIM}{hex_val}{RESET}")

    print()


if __name__ == '__main__':
    main()
