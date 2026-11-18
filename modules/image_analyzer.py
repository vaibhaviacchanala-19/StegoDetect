import math
from statistics import mean, pstdev

from PIL import Image


def _channel_stats(image):
    channels = {"r": [], "g": [], "b": []}
    for pixel in image.getdata():
        r, g, b = pixel[:3]
        channels["r"].append(r)
        channels["g"].append(g)
        channels["b"].append(b)
    return {name: {"mean": round(mean(vals), 2), "stdev": round(pstdev(vals), 2) if len(vals) > 1 else 0.0} for name, vals in channels.items()}


def _lsb_summary(image):
    bits = []
    for pixel in image.getdata():
        bits.append(pixel[0] & 1)
        bits.append(pixel[1] & 1)
        bits.append(pixel[2] & 1)
    odd_count = sum(1 for bit in bits if bit == 1)
    even_count = len(bits) - odd_count
    return {
        "odd_lsb_count": odd_count,
        "even_lsb_count": even_count,
        "odd_lsb_ratio": round((odd_count / len(bits)) if bits else 0.0, 4),
        "dominant_lsb": "odd" if odd_count > even_count else "even",
    }


def analyze_image(file_path: str):
    try:
        image = Image.open(file_path).convert("RGB")
    except Exception as exc:
        return {"tool_name": "Image Analysis", "available": False, "status": "error", "message": str(exc), "findings": []}

    width, height = image.size
    channel_stats = _channel_stats(image)
    lsb_summary = _lsb_summary(image)
    return {
        "tool_name": "Image Analysis",
        "available": True,
        "status": "ok",
        "dimensions": {"width": width, "height": height},
        "channel_stats": channel_stats,
        "lsb_summary": lsb_summary,
        "findings": [{
            "finding_name": "Basic image statistics",
            "description": "Image dimensions and channel statistics were computed from the actual file pixels.",
            "severity": "low",
            "analysis_status": "inconclusive",
        }],
    }
