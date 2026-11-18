#!/usr/bin/env python3
"""Generate small safe sample files for UI and validation testing."""

import io
from pathlib import Path

from PIL import Image

ROOT = Path(__file__).resolve().parents[1]
SAMPLES = ROOT / "samples"
SAMPLES.mkdir(exist_ok=True)

# Create valid image files with Pillow so they pass the app's validation steps.
image_png = Image.new("RGB", (32, 32), color=(30, 144, 255))
png_buffer = io.BytesIO()
image_png.save(png_buffer, format="PNG")
(SAMPLES / "safe_sample.png").write_bytes(png_buffer.getvalue())

image_jpeg = Image.new("RGB", (32, 32), color=(40, 200, 120))
jpeg_buffer = io.BytesIO()
image_jpeg.save(jpeg_buffer, format="JPEG")
(SAMPLES / "safe_sample.jpeg").write_bytes(jpeg_buffer.getvalue())

TXT_BYTES = b"This is a safe example file for dashboard validation.\nURL https://example.com\nPowerShell -NoProfile -Command \"Write-Host sample\"\n"
ZIP_BYTES = b"PK\x03\x04sample-safe-archive"

(SAMPLES / "safe_sample.txt").write_bytes(TXT_BYTES)
(SAMPLES / "safe_sample.zip").write_bytes(ZIP_BYTES)

print(f"Safe sample files generated in {SAMPLES}")
