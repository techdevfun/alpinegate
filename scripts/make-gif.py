#!/usr/bin/env python3
"""Render demo/transcript.txt as a terminal-typing GIF (PIL, DejaVuSansMono).
The transcript is generated from real CLI runs (see build note); this script
only renders it, never edits the content."""
from PIL import Image, ImageDraw, ImageFont
import os

W, H = 1240, 820
BG = (18, 18, 24)
FG = (220, 220, 220)
DIM = (150, 150, 160)
GREEN = (120, 220, 130)
YELLOW = (235, 200, 100)
RED = (240, 110, 110)
CYAN = (120, 200, 230)

font = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf", 12)
bold = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSansMono-Bold.ttf", 12)
LINE_H = 16

lines = open("demo/transcript.txt").read().splitlines()

def color_for(line: str):
    if line.startswith("$"):
        return GREEN
    if "EXPOSED" in line and "fixtures/exposed" in line:
        return RED
    if line.startswith("fixtures/exposed:"):
        return RED
    if line.startswith("fixtures/patched:"):
        return GREEN
    if line.startswith("exit: 1"):
        return RED
    if line.startswith("exit: 0"):
        return GREEN
    if line.startswith("alpinegate playbook"):
        return CYAN
    if line.startswith("1. Close") or line.startswith("2. Then") or line.startswith("3. Check"):
        return YELLOW
    if line.strip().startswith("apk upgrade") or "rc-service sshd restart" in line:
        return CYAN
    return FG

frames = []
canvas: list[tuple[str, tuple]] = []

# Title card (3s): what the demo shows
title = Image.new("RGB", (W, H), BG)
d = ImageDraw.Draw(title)
d.text((14, 200), "alpinegate — is this image exposed to CVE-2026-123158?", font=bold, fill=GREEN)
d.text((14, 250), "1. scan a pre-fix Alpine 3.18 rootfs and a patched one", font=font, fill=FG)
d.text((14, 280), "2. one row is EXPOSED, one is SAFE — exit 1", font=font, fill=FG)
d.text((14, 310), "3. playbook prints the first-hour stopgap", font=font, fill=FG)
d.text((14, 380), "zero-dep CLI · no network · no login attempts", font=font, fill=DIM)
for _ in range(50):
    frames.append(title.copy())

def render(canvas_tmp):
    img = Image.new("RGB", (W, H), BG)
    d = ImageDraw.Draw(img)
    y = 14
    for text, color in canvas_tmp:
        f = bold if text.startswith("$") else font
        d.text((14, y), text, font=f, fill=color)
        y += LINE_H
        if y > H - 30:
            break
    d.rectangle([14, H - 24, 22, H - 12], fill=GREEN)
    return img

for line in lines:
    color = color_for(line)
    step = max(1, len(line) // 12)
    for i in range(0, len(line) + 1, step):
        frames.append(render(canvas + [(line[:i], color)]))
    canvas.append((line, color))
    if line.startswith("exit:"):
        for _ in range(14):
            frames.append(frames[-1].copy())

for _ in range(30):
    frames.append(frames[-1].copy())

frames[0].save(
    "demo/alpinegate-demo.gif",
    save_all=True,
    append_images=frames[1:],
    duration=60,
    loop=0,
)
print(f"frames={len(frames)} size={os.path.getsize('demo/alpinegate-demo.gif')} duration~{len(frames)*60/1000:.1f}s")
