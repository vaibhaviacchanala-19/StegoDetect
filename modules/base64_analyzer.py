import base64
import re

from modules.strings_analyzer import analyze_strings

BASE64_RE = re.compile(r"(?<![A-Za-z0-9+/=])(?:[A-Za-z0-9+/]{16,}={0,2})(?![A-Za-z0-9+/=])")


def _safe_decode(value: str):
    candidate = value.strip().replace("\r", "").replace("\n", "")
    if len(candidate) % 4:
        candidate += "=" * ((4 - len(candidate) % 4) % 4)
    try:
        decoded = base64.b64decode(candidate, validate=False)
    except Exception:
        return None, "decode_failed"
    text = decoded.decode("utf-8", errors="ignore")
    if not text:
        return None, "empty_output"
    return text, "decoded"


def analyze_base64(file_path: str):
    string_analysis = analyze_strings(file_path)
    results = []
    seen = set()
    for item in string_analysis.get("findings", []):
        candidate = item.get("extracted_string", "")
        if not candidate:
            continue
        fragments = [frag.strip() for frag in re.split(r"[\r\n\t]+", candidate) if frag.strip()]
        for fragment in fragments:
            if not BASE64_RE.fullmatch(fragment):
                continue
            if fragment in seen:
                continue
            seen.add(fragment)
            decoded, status = _safe_decode(fragment)
            results.append({
                "original_string": fragment,
                "decoded_output": decoded,
                "decoding_status": status,
                "category": item.get("category"),
            })

    return {
        "tool_name": "Base64 Analysis",
        "available": True,
        "status": "ok" if results else "no_findings",
        "results": results,
        "summary": f"{len(results)} potential Base64 payload(s) identified." if results else "No clear Base64 candidates detected.",
    }
