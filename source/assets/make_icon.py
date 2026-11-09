"""Renders the Hushwing app icon (shield + download arrow) to hushwing.ico and hushwing.png.

Run:  py -3.12 assets/make_icon.py
"""
from pathlib import Path

from PIL import Image, ImageChops, ImageDraw, ImageFilter

OUT = Path(__file__).resolve().parent
S = 1024  # master size; everything is drawn large then downsampled


def lerp(a, b, t):
    return tuple(int(a[i] + (b[i] - a[i]) * t) for i in range(len(a)))


def gradient(size, c1, c2, diagonal=True):
    w, h = size
    g = Image.new("RGBA", size)
    px = g.load()
    for y in range(h):
        for x in range(w):
            t = ((x / w) * 0.35 + (y / h) * 0.65) if diagonal else y / h
            px[x, y] = lerp(c1, c2, t)
    return g


def bezier(p0, p1, p2, steps=60):
    return [
        (
            (1 - t) ** 2 * p0[0] + 2 * (1 - t) * t * p1[0] + t ** 2 * p2[0],
            (1 - t) ** 2 * p0[1] + 2 * (1 - t) * t * p1[1] + t ** 2 * p2[1],
        )
        for t in (i / steps for i in range(steps + 1))
    ]


def shield_points(scale=1.0, cx=0.5, cy=0.52):
    # unit shield, centred on (0.5, 0.5)
    pts = []
    pts += bezier((0.20, 0.24), (0.36, 0.22), (0.50, 0.12))  # top-left shoulder up to peak
    pts += bezier((0.50, 0.12), (0.64, 0.22), (0.80, 0.24))  # peak down to top-right
    pts += bezier((0.80, 0.24), (0.82, 0.62), (0.50, 0.90))  # right side down to tip
    pts += bezier((0.50, 0.90), (0.18, 0.62), (0.20, 0.24))  # tip back up the left side
    return [((x - 0.5) * scale * S + cx * S, (y - 0.5) * scale * S + cy * S) for x, y in pts]


def mask_from(draw_fn):
    m = Image.new("L", (S, S), 0)
    draw_fn(ImageDraw.Draw(m))
    return m


def render() -> Image.Image:
    img = Image.new("RGBA", (S, S), (0, 0, 0, 0))

    # 1. rounded-square tile with deep navy -> indigo gradient
    tile_mask = mask_from(lambda d: d.rounded_rectangle((40, 40, S - 40, S - 40), radius=230, fill=255))
    tile = gradient((S, S), (13, 18, 38, 255), (49, 30, 112, 255))
    img.paste(tile, (0, 0), tile_mask)

    # soft top highlight on the tile
    hl = mask_from(lambda d: d.ellipse((-200, -620, S + 200, 420), fill=70))
    hl = ImageChops.multiply(hl.filter(ImageFilter.GaussianBlur(40)), tile_mask).point(lambda v: int(v * 0.6))
    img = Image.alpha_composite(img, Image.merge("RGBA", (*[Image.new("L", (S, S), 255)] * 3, hl)))

    # 2. glow + drop shadow behind shield
    shield = shield_points(scale=0.98)
    glow = mask_from(lambda d: d.polygon(shield, fill=255)).filter(ImageFilter.GaussianBlur(60))
    glow_layer = Image.new("RGBA", (S, S), (56, 189, 248, 0))
    glow_layer.putalpha(ImageChops.multiply(glow.point(lambda v: int(v * 0.55)), tile_mask))
    img = Image.alpha_composite(img, glow_layer)

    # 3. shield body: cyan -> violet gradient
    shield_mask = mask_from(lambda d: d.polygon(shield, fill=255))
    body = gradient((S, S), (34, 211, 238, 255), (139, 92, 246, 255))
    layer = Image.new("RGBA", (S, S), (0, 0, 0, 0))
    layer.paste(body, (0, 0), shield_mask)
    img = Image.alpha_composite(img, layer)

    # inner bevel: lighter left half for depth
    left = mask_from(lambda d: d.polygon([(0, 0), (S * 0.5, 0), (S * 0.5, S), (0, S)], fill=45))
    bevel = ImageChops.multiply(left, shield_mask)
    img = Image.alpha_composite(img, Image.merge("RGBA", (*[Image.new("L", (S, S), 255)] * 3, bevel)))

    # 4. download arrow + tray, in near-white, with subtle shadow
    def arrow(d, dx=0, dy=0, fill=255):
        cx = S * 0.5 + dx
        shaft_w, top, mid = S * 0.075, S * 0.30 + dy, S * 0.55 + dy
        d.rounded_rectangle((cx - shaft_w, top, cx + shaft_w, mid + 10), radius=int(shaft_w * 0.6), fill=fill)
        head_w, tip = S * 0.19, S * 0.70 + dy
        d.polygon([(cx - head_w, mid - 20), (cx + head_w, mid - 20), (cx, tip)], fill=fill)

    shadow = mask_from(lambda d: arrow(d, 0, 14, 150)).filter(ImageFilter.GaussianBlur(14))
    shadow = ImageChops.multiply(shadow, shield_mask)
    sh_layer = Image.new("RGBA", (S, S), (20, 10, 60, 0))
    sh_layer.putalpha(shadow)
    img = Image.alpha_composite(img, sh_layer)

    arrow_mask = mask_from(arrow)
    white = Image.new("RGBA", (S, S), (248, 250, 255, 255))
    a_layer = Image.new("RGBA", (S, S), (0, 0, 0, 0))
    a_layer.paste(white, (0, 0), arrow_mask)
    img = Image.alpha_composite(img, a_layer)
    return img


def main():
    img = render()
    img.save(OUT / "hushwing.png")
    img.resize((256, 256), Image.LANCZOS).save(OUT / "hushwing_256.png")
    sizes = [(16, 16), (20, 20), (24, 24), (32, 32), (40, 40), (48, 48), (64, 64), (128, 128), (256, 256)]
    img.save(OUT / "hushwing.ico", sizes=sizes)
    print("wrote", OUT / "hushwing.ico")


if __name__ == "__main__":
    main()
