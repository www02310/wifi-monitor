"""生成程序图标 app.ico（可复现，不需要外部素材）。

用法：python make_icon.py [输出路径]

设计：深色圆角底 + 绿色 WiFi 弧形信号 + 底部圆点，
在 16px 下仍能看出「WiFi」。用 4 倍超采样再缩小，避免锯齿。
"""

import os
import sys

from PIL import Image, ImageDraw

SCALE = 4                     # 超采样倍数
SIZE = 256                    # 最终尺寸
CANVAS = SIZE * SCALE

BG_TOP = (15, 23, 42)         # #0f172a
BG_BOTTOM = (30, 41, 59)      # #1e293b
RING = (51, 65, 85)           # #334155 边框
ARC = (52, 211, 153)          # #34d399 主色（健康绿）
DOT = (110, 231, 183)         # #6ee7b7

ICO_SIZES = [256, 128, 64, 48, 32, 24, 16]


def _vertical_gradient(size, top, bottom):
    image = Image.new("RGB", (1, size), top)
    draw = ImageDraw.Draw(image)
    for y in range(size):
        ratio = y / max(1, size - 1)
        draw.point(
            (0, y),
            fill=(
                round(top[0] + (bottom[0] - top[0]) * ratio),
                round(top[1] + (bottom[1] - top[1]) * ratio),
                round(top[2] + (bottom[2] - top[2]) * ratio),
            ),
        )
    return image.resize((size, size))


def build_icon(path="app.ico"):
    canvas = CANVAS
    image = Image.new("RGBA", (canvas, canvas), (0, 0, 0, 0))

    # 圆角底：先做渐变，再用圆角蒙版裁出来
    radius = int(canvas * 0.22)
    mask = Image.new("L", (canvas, canvas), 0)
    ImageDraw.Draw(mask).rounded_rectangle(
        (0, 0, canvas - 1, canvas - 1), radius=radius, fill=255
    )
    background = _vertical_gradient(canvas, BG_TOP, BG_BOTTOM).convert("RGBA")
    image.paste(background, (0, 0), mask)

    draw = ImageDraw.Draw(image)
    draw.rounded_rectangle(
        (0, 0, canvas - 1, canvas - 1), radius=radius,
        outline=RING + (255,), width=max(2, int(canvas * 0.012)),
    )

    # WiFi 弧线：圆心靠下居中，三段同心弧，只画朝上的部分。
    # 弧度跨度 232°→308°（约 76°）是为了让最外圈的**两端也留在画布内**，
    # 跨度再大就会像被裁掉一样贴到左右边缘。
    center_x = canvas // 2
    center_y = int(canvas * 0.78)
    stroke = max(4, int(canvas * 0.075))
    for factor in (0.28, 0.48, 0.68):
        radius_arc = int(canvas * factor)
        bbox = (
            center_x - radius_arc, center_y - radius_arc,
            center_x + radius_arc, center_y + radius_arc,
        )
        # PIL 角度：0 在正右、顺时针增大，270 为正上
        draw.arc(bbox, start=232, end=308, fill=ARC + (255,), width=stroke)

    # 底部圆点（信号源）
    dot_radius = int(canvas * 0.055)
    draw.ellipse(
        (
            center_x - dot_radius, center_y - dot_radius,
            center_x + dot_radius, center_y + dot_radius,
        ),
        fill=DOT + (255,),
    )

    final = image.resize((SIZE, SIZE), Image.LANCZOS)
    final.save(path, format="ICO", sizes=[(s, s) for s in ICO_SIZES])
    return path


def main():
    target = sys.argv[1] if len(sys.argv) > 1 else "app.ico"
    target = os.path.abspath(target)
    build_icon(target)
    print("图标已生成：%s（%d 字节）" % (target, os.path.getsize(target)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
