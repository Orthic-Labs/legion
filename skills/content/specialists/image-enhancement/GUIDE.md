---
name: content-image-enhancement
description: Improves the quality of images, especially screenshots, by enhancing resolution, sharpness, and clarity. Perfect for preparing images for presentations, documentation, or social media posts.
---

# Image Enhancer

This skill takes your images and screenshots and makes them look better—sharper, clearer, and more professional.

## When to Use This Skill

- Improving screenshot quality for blog posts or documentation
- Enhancing images before sharing on social media
- Preparing images for presentations or reports
- Upscaling low-resolution images
- Sharpening blurry photos
- Cleaning up compressed images

## What This Skill Does

1. **Analyzes Image Quality**: Checks resolution, sharpness, and compression artifacts
2. **Enhances Resolution**: Upscales images intelligently
3. **Improves Sharpness**: Enhances edges and details
4. **Reduces Artifacts**: Cleans up compression artifacts and noise
5. **Optimizes for Use Case**: Adjusts based on intended use (web, print, social media)

## How to Use

### Basic Enhancement

```
Improve the image quality of screenshot.png
```

```
Enhance all images in this folder
```

### Specific Improvements

```
Upscale this image to 4K resolution
```

```
Sharpen this blurry screenshot
```

```
Reduce compression artifacts in this image
```

### Batch Processing

```
Improve the quality of all PNG files in this directory
```

## Script

A real Pillow-based script lives at `skills/content/specialists/image-enhancement/scripts/enhance.py`.
It performs: LANCZOS resize + UnsharpMask sharpen + optional contrast, and prints the **actual**
input/output dimensions read from the file — no fabricated measurements.

```bash
# Double size + sharpen (default)
py -3.11 skills/content/specialists/image-enhancement/scripts/enhance.py screenshot.png

# Scale to a specific width, skip sharpen
py -3.11 skills/content/specialists/image-enhancement/scripts/enhance.py screenshot.png --width 1920 --no-sharpen

# Custom output path
py -3.11 skills/content/specialists/image-enhancement/scripts/enhance.py screenshot.png --output out/enhanced.png
```

Example output (actual values from the image):
```
Input:  screenshot.png  1280x720  mode=RGB
Resized: 2560x1440
Sharpened: UnsharpMask(radius=1, percent=150, threshold=2)
Output: screenshot-enhanced.png  2560x1440
```

**Inspired by:** Lenny Rachitsky's workflow from his newsletter - used for screenshots in his articles

## Tips

- Always keeps original files as backup
- Works best with screenshots and digital images
- Can batch process entire folders
- Specify output format if needed (PNG for quality, JPG for smaller size)
- For social media, mention the platform for optimal sizing

## Common Use Cases

- **Blog Posts**: Enhance screenshots before publishing
- **Documentation**: Make UI screenshots crystal clear
- **Social Media**: Optimize images for Twitter, LinkedIn, Instagram
- **Presentations**: Upscale images for large screens
- **Print Materials**: Increase resolution for physical media

