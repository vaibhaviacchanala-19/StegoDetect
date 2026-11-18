import math
from typing import List

from PIL import Image


def shannon_entropy(data: bytes):
    if not data:
        return 0.0
    counts = {}
    for byte in data:
        counts[byte] = counts.get(byte, 0) + 1
    entropy = 0.0
    length = len(data)
    for count in counts.values():
        probability = count / length
        entropy -= probability * math.log2(probability)
    return entropy


def _window_entropy(data: bytes, window_size: int = 256):
    sections = []
    for index in range(0, len(data), window_size):
        chunk = data[index:index + window_size]
        if not chunk:
            continue
        entropy = shannon_entropy(chunk)
        sections.append({
            "offset": index,
            "size": len(chunk),
            "entropy": round(entropy, 4),
        })
    return sections


def _build_entropy_chart(sections: List[dict]):
    if not sections:
        return "<svg width='100%' height='120' viewBox='0 0 800 120' xmlns='http://www.w3.org/2000/svg'></svg>"
    max_entropy = max((item["entropy"] for item in sections), default=8.0)
    width = 800
    height = 120
    margin = 12
    step = max(1, len(sections))
    bar_width = max(2, (width - margin * 2) / max(1, len(sections)))
    bars = []
    for idx, item in enumerate(sections):
        bar_height = max(6, (item["entropy"] / max_entropy) * (height - margin * 2))
        x = idx * bar_width + margin
        y = height - margin - bar_height
        bars.append(f'<rect x="{x:.2f}" y="{y:.2f}" width="{bar_width - 1:.2f}" height="{bar_height:.2f}" fill="#4dd0ff" rx="2"/>')
    return f'<svg width="100%" height="120" viewBox="0 0 {width} {height}" xmlns="http://www.w3.org/2000/svg">' + ''.join(bars) + '</svg>'


def analyze_entropy(file_path: str):
    with open(file_path, "rb") as handle:
        data = handle.read()

    overall = shannon_entropy(data)
    sections = _window_entropy(data)
    high_regions = [item for item in sections if item["entropy"] > 7.5]

    image_entropy = None
    try:
        image = Image.open(file_path).convert("RGB")
        channel_data = []
        for channel in range(3):
            channel_bytes = b"".join(bytes([pixel[channel]]) for pixel in image.getdata())
            channel_data.append(shannon_entropy(channel_bytes))
        image_entropy = {"r": round(channel_data[0], 4), "g": round(channel_data[1], 4), "b": round(channel_data[2], 4)}
    except Exception:
        image_entropy = None

    return {
        "tool_name": "Entropy Analysis",
        "available": True,
        "overall_entropy": round(overall, 4),
        "section_entropies": sections[:32],
        "high_entropy_regions": high_regions[:10],
        "chart_svg": _build_entropy_chart(sections),
        "image_entropy": image_entropy,
        "summary": f"Overall entropy: {overall:.4f}. High-entropy regions: {len(high_regions)}.",
    }
