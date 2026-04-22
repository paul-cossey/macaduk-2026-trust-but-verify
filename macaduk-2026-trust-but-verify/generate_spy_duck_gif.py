#!/usr/bin/env python3
"""
Generate an animated GIF of the spy duck peeking from behind a wall.
Recreates the CSS animation from spy_duck_peek_clean.html.
"""

import io
import math
import cairosvg
from PIL import Image

# Scene dimensions
SCENE_W = 860
SCENE_H = 400
BG_COLOUR = (15, 15, 15)
WALL_COLOUR = (18, 18, 30)
WALL_EDGE = (37, 37, 53)

# Duck SVG (static, no CSS animation)
DUCK_SVG = '''<svg viewBox="0 0 164 210" width="164" height="210"
  xmlns="http://www.w3.org/2000/svg">
  <ellipse cx="88" cy="203" rx="52" ry="6" fill="#050506"/>
  <ellipse cx="93" cy="138" rx="57" ry="45" fill="#FFD700"/>
  <path d="M40,144 Q40,183 93,183 Q146,183 146,144
    Q142,168 93,174 Q44,168 40,144Z" fill="#D4AB00"/>
  <path d="M149,122 Q168,100 158,78 Q149,96 145,120Z"
    fill="#FFDE00"/>
  <ellipse cx="79" cy="112" rx="23" ry="18" fill="#FFD700"/>
  <circle cx="64" cy="79" r="35" fill="#FFD700"/>
  <ellipse cx="51" cy="65" rx="12" ry="10"
    fill="#FFEE66" opacity="0.24"/>
  <path d="M33,71 Q3,76 3,83 Q3,90 33,85Z" fill="#FF8800"/>
  <path d="M33,77 Q10,78 10,82 Q16,83 33,81" fill="#CC6000"/>
  <path d="M29,47 L29,16 Q29,8 64,8 Q99,8 99,16 L99,47Z"
    fill="#0D0D0D"/>
  <ellipse cx="64" cy="11" rx="35" ry="7" fill="#0D0D0D"/>
  <ellipse cx="64" cy="47" rx="49" ry="9" fill="#1A1A1A"/>
  <rect x="29" y="41" width="70" height="6" rx="1"
    fill="#CC2424"/>
  <path d="M51,10 Q64,8 77,10 Q64,14 51,10Z" fill="#0A0A0A"/>
  <path d="M32,18 Q39,10 64,9 Q56,13 32,23Z"
    fill="#2A2A2A" opacity="0.5"/>
  <rect x="29" y="67" width="21" height="14" rx="4"
    fill="#060608" stroke="#282828" stroke-width="1.5"/>
  <rect x="53" y="67" width="20" height="14" rx="4"
    fill="#060608" stroke="#282828" stroke-width="1.5"/>
  <rect x="50" y="71" width="3" height="5" rx="1"
    fill="#303030"/>
  <line x1="29" y1="74" x2="18" y2="73" stroke="#303030"
    stroke-width="2" stroke-linecap="round"/>
  <line x1="73" y1="74" x2="83" y2="77" stroke="#303030"
    stroke-width="2" stroke-linecap="round"/>
  <rect x="31" y="69" width="7" height="3" rx="1"
    fill="#0C0C24" opacity="0.7"/>
  <rect x="55" y="69" width="7" height="3" rx="1"
    fill="#0C0C24" opacity="0.7"/>
  <ellipse cx="51" cy="128" rx="19" ry="10" fill="#CFAB00"
    transform="rotate(-28 51 128)"/>
  <ellipse cx="28" cy="185" rx="28" ry="5" fill="#040404"/>
  <rect x="3" y="146" width="50" height="35" rx="4"
    fill="#3B2710" stroke="#563A18" stroke-width="1.5"/>
  <line x1="3" y1="160" x2="53" y2="160"
    stroke="#251606" stroke-width="1.5"/>
  <path d="M13,146 Q28,134 43,146" fill="none"
    stroke="#6A3C18" stroke-width="3" stroke-linecap="round"/>
  <rect x="18" y="156" width="20" height="8" rx="2"
    fill="#7A5C20"/>
  <rect x="21" y="154" width="14" height="5" rx="2"
    fill="#9A7830"/>
  <rect x="5" y="168" width="46" height="11" rx="2"
    fill="#CC2424"/>
  <text x="28" y="177" text-anchor="middle"
    font-family="Courier New,monospace" font-size="5.2"
    font-weight="bold" fill="#FFFFFF"
    letter-spacing="0.8">TOP SECRET</text>
  <ellipse cx="63" cy="181" rx="20" ry="7" fill="#E06800"
    transform="rotate(-10 63 181)"/>
  <ellipse cx="97" cy="183" rx="18" ry="7" fill="#E06800"
    transform="rotate(8 97 183)"/>
</svg>'''

DUCK_W = 164
DUCK_H = 210
WALL_W = 270
WALL_EDGE_W = 5
WALL_SHADOW_W = 18


def _render_duck():
    """Render the duck SVG to a PIL Image with transparency."""
    png_data = cairosvg.svg2png(
        bytestring=DUCK_SVG.encode('utf-8'),
        output_width=DUCK_W * 2,
        output_height=DUCK_H * 2,
    )
    return Image.open(io.BytesIO(png_data)).convert('RGBA')


def _ease_in_out(t):
    """CSS ease-in-out approximation."""
    return 0.5 * (1 - math.cos(math.pi * t))


def _peek_offset(progress):
    """
    CSS keyframes:
      0%-12%:  translateX(160)  — hidden
      30%-68%: translateX(0)    — visible
      85%-100%: translateX(160) — hidden
    Returns x-offset in pixels.
    """
    p = progress % 1.0
    if p <= 0.12:
        return 160.0
    elif p <= 0.30:
        t = (p - 0.12) / (0.30 - 0.12)
        return 160.0 * (1.0 - _ease_in_out(t))
    elif p <= 0.68:
        return 0.0
    elif p <= 0.85:
        t = (p - 0.68) / (0.85 - 0.68)
        return 160.0 * _ease_in_out(t)
    else:
        return 160.0


def _bob_offset(progress):
    """
    CSS keyframes:
      0%,100%: translateY(0)
      50%: translateY(-5)
    3.5s cycle.
    """
    return -5.0 * math.sin(2.0 * math.pi * progress)


def generate_gif(output_path, fps=20, duration_s=7.0):
    """Generate the animated GIF."""
    duck_img = _render_duck()

    # Scale duck down to 1x for compositing
    duck_1x = duck_img.resize(
        (DUCK_W, DUCK_H), Image.LANCZOS)

    total_frames = int(fps * duration_s)
    frames = []

    # Duck base position (from CSS):
    # right: 196px, bottom: 20px
    duck_base_x = SCENE_W - 196 - DUCK_W
    duck_base_y = SCENE_H - 20 - DUCK_H

    bob_period = 3.5  # seconds

    # Pre-build the static background (wall + bricks)
    bg = Image.new('RGB', (SCENE_W, SCENE_H), BG_COLOUR)
    bg_pixels = bg.load()

    # Wall shadow
    shadow_x = SCENE_W - WALL_W - WALL_EDGE_W - WALL_SHADOW_W
    for sx in range(WALL_SHADOW_W):
        alpha = int(15 * (sx / WALL_SHADOW_W))
        c = (max(0, BG_COLOUR[0] - alpha),
             max(0, BG_COLOUR[1] - alpha),
             max(0, BG_COLOUR[2] - alpha))
        for sy in range(SCENE_H):
            bg_pixels[shadow_x + sx, sy] = c

    # Wall edge
    edge_x = SCENE_W - WALL_W - WALL_EDGE_W
    for ex in range(WALL_EDGE_W):
        for ey in range(SCENE_H):
            bg_pixels[edge_x + ex, ey] = WALL_EDGE

    # Wall with brick mortar
    wall_x = SCENE_W - WALL_W
    for wx in range(WALL_W):
        for wy in range(SCENE_H):
            if wy % 33 == 32:
                bg_pixels[wall_x + wx, wy] = (8, 8, 16)
            else:
                bg_pixels[wall_x + wx, wy] = WALL_COLOUR

    for i in range(total_frames):
        t = i / total_frames
        t_sec = t * duration_s

        peek_x = _peek_offset(t)
        bob_y = _bob_offset(
            (t_sec % bob_period) / bob_period)

        # Start from pre-built background
        frame = bg.copy()

        # Paste duck
        dx = int(duck_base_x + peek_x)
        dy = int(duck_base_y + bob_y)
        frame.paste(duck_1x, (dx, dy), duck_1x)

        # Re-draw wall over duck (wall is in front)
        wall_region = bg.crop(
            (shadow_x, 0, SCENE_W, SCENE_H))
        frame.paste(wall_region, (shadow_x, 0))

        frames.append(frame)

    # Save as GIF
    frame_duration_ms = int(1000 / fps)
    frames[0].save(
        output_path,
        save_all=True,
        append_images=frames[1:],
        duration=frame_duration_ms,
        loop=0,
        optimize=True,
    )
    print(f"  Spy duck GIF: {output_path} "
          f"({len(frames)} frames)")


if __name__ == '__main__':
    generate_gif('spy_duck_peek.gif')
