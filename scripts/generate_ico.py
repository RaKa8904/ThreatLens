"""
ThreatLens Custom Windows Icon Generator
========================================
Renders Favicon.svg vector design into high-resolution native Windows ICO icon format
supporting 256x256, 64x64, 48x48, 32x32, and 16x16 icon mipmaps.
"""

import os
from PIL import Image, ImageDraw

def render_threatlens_icon(output_path: str = "ThreatLens.ico"):
    sizes = [(256, 256), (64, 64), (48, 48), (32, 32), (16, 16)]
    images = []

    for width, height in sizes:
        img = Image.new("RGBA", (width, height), (0, 0, 0, 0))
        draw = ImageDraw.Draw(img)

        # Scale factor relative to 32x32 design
        scale = width / 32.0

        # 1. Base dark background badge (#0b0f19) with rounded corners
        bg_rect = [0, 0, width - 1, height - 1]
        rx = int(7 * scale)
        draw.rounded_rectangle(bg_rect, radius=rx, fill=(11, 15, 25, 255))

        # 2. Outer Lens Ring (#00f0ff cyan)
        cx, cy = width / 2.0, height / 2.0
        r_outer = 9 * scale
        ring_bbox = [cx - r_outer, cy - r_outer, cx + r_outer, cy + r_outer]
        stroke_w = max(1, int(2 * scale))
        draw.ellipse(ring_bbox, outline=(0, 240, 255, 255), width=stroke_w)

        # 3. Crosshair Reticle Ticks (#38bdf8 sky blue)
        tick_len = 4 * scale
        # Top tick
        draw.line([(cx, 3 * scale), (cx, 3 * scale + tick_len)], fill=(56, 189, 248, 255), width=stroke_w)
        # Bottom tick
        draw.line([(cx, 29 * scale - tick_len), (cx, 29 * scale)], fill=(56, 189, 248, 255), width=stroke_w)
        # Left tick
        draw.line([(3 * scale, cy), (3 * scale + tick_len, cy)], fill=(56, 189, 248, 255), width=stroke_w)
        # Right tick
        draw.line([(29 * scale - tick_len, cy), (29 * scale, cy)], fill=(56, 189, 248, 255), width=stroke_w)

        # 4. Focal Threat Core Node (#ff0055 hot pink/red)
        r_core = 3.5 * scale
        core_bbox = [cx - r_core, cy - r_core, cx + r_core, cy + r_core]
        draw.ellipse(core_bbox, fill=(255, 0, 85, 255))

        images.append(img)

    # Save as multi-resolution ICO file
    images[0].save(output_path, format="ICO", sizes=[(im.width, im.height) for im in images], append_images=images[1:])
    print(f"[*] Created ThreatLens icon file: {output_path}")

if __name__ == "__main__":
    render_threatlens_icon()
