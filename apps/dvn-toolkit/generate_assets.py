#!/usr/bin/env python3
"""Generate app icon and presplash for DVN Toolkit"""

from PIL import Image, ImageDraw, ImageFont
import os

# Colors from cyberpunk theme
BG_COLOR = (10, 10, 18)  # #0a0a12
ACCENT_COLOR = (0, 255, 159)  # #00ff9f
ACCENT_SECONDARY = (255, 0, 255)  # #ff00ff

def create_icon(size=512):
    """Create app icon"""
    img = Image.new('RGBA', (size, size), BG_COLOR)
    draw = ImageDraw.Draw(img)

    # Draw outer ring
    padding = size // 10
    draw.ellipse(
        [padding, padding, size - padding, size - padding],
        outline=ACCENT_COLOR,
        width=size // 25
    )

    # Draw inner hexagon-like shape
    center = size // 2
    radius = size // 3

    # Draw "DVN" text
    try:
        # Try to use a monospace font
        font_size = size // 4
        font = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSansMono-Bold.ttf", font_size)
    except:
        font = ImageFont.load_default()

    text = "DVN"
    bbox = draw.textbbox((0, 0), text, font=font)
    text_width = bbox[2] - bbox[0]
    text_height = bbox[3] - bbox[1]

    x = (size - text_width) // 2
    y = (size - text_height) // 2 - size // 20

    # Draw text shadow
    draw.text((x + 3, y + 3), text, font=font, fill=(0, 100, 60))
    # Draw main text
    draw.text((x, y), text, font=font, fill=ACCENT_COLOR)

    # Draw small "TOOLKIT" below
    try:
        small_font = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf", size // 12)
    except:
        small_font = ImageFont.load_default()

    sub_text = "TOOLKIT"
    sub_bbox = draw.textbbox((0, 0), sub_text, font=small_font)
    sub_width = sub_bbox[2] - sub_bbox[0]
    sub_x = (size - sub_width) // 2
    sub_y = y + text_height + size // 20

    draw.text((sub_x, sub_y), sub_text, font=small_font, fill=ACCENT_SECONDARY)

    # Draw decorative corners
    corner_len = size // 8
    corner_width = size // 50

    # Top-left
    draw.line([(padding//2, padding//2), (padding//2 + corner_len, padding//2)], fill=ACCENT_SECONDARY, width=corner_width)
    draw.line([(padding//2, padding//2), (padding//2, padding//2 + corner_len)], fill=ACCENT_SECONDARY, width=corner_width)

    # Top-right
    draw.line([(size - padding//2, padding//2), (size - padding//2 - corner_len, padding//2)], fill=ACCENT_SECONDARY, width=corner_width)
    draw.line([(size - padding//2, padding//2), (size - padding//2, padding//2 + corner_len)], fill=ACCENT_SECONDARY, width=corner_width)

    # Bottom-left
    draw.line([(padding//2, size - padding//2), (padding//2 + corner_len, size - padding//2)], fill=ACCENT_SECONDARY, width=corner_width)
    draw.line([(padding//2, size - padding//2), (padding//2, size - padding//2 - corner_len)], fill=ACCENT_SECONDARY, width=corner_width)

    # Bottom-right
    draw.line([(size - padding//2, size - padding//2), (size - padding//2 - corner_len, size - padding//2)], fill=ACCENT_SECONDARY, width=corner_width)
    draw.line([(size - padding//2, size - padding//2), (size - padding//2, size - padding//2 - corner_len)], fill=ACCENT_SECONDARY, width=corner_width)

    return img

def create_presplash(width=512, height=512):
    """Create presplash image"""
    img = Image.new('RGBA', (width, height), BG_COLOR)
    draw = ImageDraw.Draw(img)

    # Draw centered DVN text
    try:
        font = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSansMono-Bold.ttf", width // 4)
    except:
        font = ImageFont.load_default()

    text = "DVN"
    bbox = draw.textbbox((0, 0), text, font=font)
    text_width = bbox[2] - bbox[0]
    text_height = bbox[3] - bbox[1]

    x = (width - text_width) // 2
    y = (height - text_height) // 2 - 30

    draw.text((x, y), text, font=font, fill=ACCENT_COLOR)

    # Draw loading text
    try:
        small_font = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf", width // 16)
    except:
        small_font = ImageFont.load_default()

    loading_text = "Loading..."
    load_bbox = draw.textbbox((0, 0), loading_text, font=small_font)
    load_width = load_bbox[2] - load_bbox[0]
    load_x = (width - load_width) // 2
    load_y = y + text_height + 40

    draw.text((load_x, load_y), loading_text, font=small_font, fill=ACCENT_SECONDARY)

    return img

def create_adaptive_icons():
    """Create adaptive icon foreground and background for Android 8+"""
    # Foreground (the DVN logo, smaller with more padding for safe zone)
    fg_size = 512
    fg = Image.new('RGBA', (fg_size, fg_size), (0, 0, 0, 0))
    draw = ImageDraw.Draw(fg)

    # Draw in center with safe zone margins (72dp safe zone for 108dp icon)
    # That's 33% margins on each side
    margin = int(fg_size * 0.15)  # 15% margin for visibility

    try:
        font = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSansMono-Bold.ttf", fg_size // 4)
    except:
        font = ImageFont.load_default()

    text = "DVN"
    bbox = draw.textbbox((0, 0), text, font=font)
    text_width = bbox[2] - bbox[0]
    text_height = bbox[3] - bbox[1]

    x = (fg_size - text_width) // 2
    y = (fg_size - text_height) // 2

    draw.text((x, y), text, font=font, fill=ACCENT_COLOR)

    # Background (solid color)
    bg = Image.new('RGBA', (fg_size, fg_size), BG_COLOR)

    return fg, bg

if __name__ == '__main__':
    assets_dir = os.path.join(os.path.dirname(__file__), 'assets')
    os.makedirs(assets_dir, exist_ok=True)

    print("Generating app icon...")
    icon = create_icon(512)
    icon.save(os.path.join(assets_dir, 'icon.png'))
    print(f"  Saved: {assets_dir}/icon.png")

    print("Generating presplash...")
    presplash = create_presplash(512, 512)
    presplash.save(os.path.join(assets_dir, 'presplash.png'))
    print(f"  Saved: {assets_dir}/presplash.png")

    print("Generating adaptive icons...")
    fg, bg = create_adaptive_icons()
    fg.save(os.path.join(assets_dir, 'icon_fg.png'))
    bg.save(os.path.join(assets_dir, 'icon_bg.png'))
    print(f"  Saved: {assets_dir}/icon_fg.png")
    print(f"  Saved: {assets_dir}/icon_bg.png")

    print("\nAll assets generated successfully!")
