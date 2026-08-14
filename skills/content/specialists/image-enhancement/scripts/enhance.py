"""
enhance.py — local image enhancement via Pillow.

Usage:
  py -3.11 enhance.py INPUT [--scale FACTOR | --width PX] [--output PATH]
                          [--no-sharpen] [--contrast FACTOR]

Defaults: scale=2.0, sharpen radius=1 percent=150 threshold=2, contrast=1.0 (none).
Output path defaults to <input-stem>-enhanced.<ext> alongside the input.

Prints actual input and output dimensions read from the image — no fabricated numbers.
"""
import argparse
import sys
from pathlib import Path

try:
    from PIL import Image, ImageFilter, ImageEnhance
except ImportError:
    sys.exit("Pillow is not installed. Run: py -3.11 -m pip install Pillow")


def parse_args():
    p = argparse.ArgumentParser(description="Enhance an image with Pillow.")
    p.add_argument("input", help="Input image path")
    p.add_argument("--scale", type=float, default=None,
                   help="Scale factor (e.g. 2.0 to double). Exclusive with --width.")
    p.add_argument("--width", type=int, default=None,
                   help="Target width in pixels; height is scaled proportionally. Exclusive with --scale.")
    p.add_argument("--output", default=None,
                   help="Output path. Defaults to <stem>-enhanced.<ext>.")
    p.add_argument("--no-sharpen", action="store_true",
                   help="Skip unsharp mask sharpening pass.")
    p.add_argument("--contrast", type=float, default=1.0,
                   help="Contrast enhancement factor (1.0 = unchanged, 1.1 = slight boost).")
    return p.parse_args()


def main():
    args = parse_args()

    src = Path(args.input)
    if not src.exists():
        sys.exit(f"File not found: {src}")

    if args.scale is not None and args.width is not None:
        sys.exit("--scale and --width are mutually exclusive.")

    img = Image.open(src)
    orig_w, orig_h = img.size
    mode = img.mode
    print(f"Input:  {src.name}  {orig_w}x{orig_h}  mode={mode}")

    # --- resize ---
    if args.width is not None:
        ratio = args.width / orig_w
        new_w = args.width
        new_h = round(orig_h * ratio)
    elif args.scale is not None:
        new_w = round(orig_w * args.scale)
        new_h = round(orig_h * args.scale)
    else:
        new_w = round(orig_w * 2.0)
        new_h = round(orig_h * 2.0)

    if (new_w, new_h) != (orig_w, orig_h):
        img = img.resize((new_w, new_h), Image.LANCZOS)
        print(f"Resized: {new_w}x{new_h}")
    else:
        print(f"No resize (same dims: {new_w}x{new_h})")

    # --- sharpen ---
    if not args.no_sharpen:
        img = img.filter(ImageFilter.UnsharpMask(radius=1, percent=150, threshold=2))
        print("Sharpened: UnsharpMask(radius=1, percent=150, threshold=2)")

    # --- contrast ---
    if args.contrast != 1.0:
        img = ImageEnhance.Contrast(img).enhance(args.contrast)
        print(f"Contrast: factor={args.contrast}")

    # --- output ---
    if args.output:
        out = Path(args.output)
    else:
        out = src.with_name(f"{src.stem}-enhanced{src.suffix}")

    out.parent.mkdir(parents=True, exist_ok=True)
    img.save(out)

    # confirm real output dimensions
    with Image.open(out) as check:
        out_w, out_h = check.size
    print(f"Output: {out}  {out_w}x{out_h}")


if __name__ == "__main__":
    main()
