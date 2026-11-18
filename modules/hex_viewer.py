def build_hex_preview(file_path: str, rows_limit: int = 64):
    with open(file_path, "rb") as handle:
        data = handle.read()

    header = data[:32]
    trailer = data[-32:] if len(data) > 32 else data
    preview = []
    for offset in range(0, min(len(data), rows_limit * 16), 16):
        chunk = data[offset:offset + 16]
        hex_bytes = " ".join(f"{byte:02x}" for byte in chunk)
        ascii_chunk = "".join(chr(byte) if 32 <= byte < 127 else "." for byte in chunk)
        preview.append({
            "offset": offset,
            "hex": hex_bytes,
            "ascii": ascii_chunk,
        })

    return {
        "tool_name": "Hex Viewer",
        "available": True,
        "header": {
            "offset": 0,
            "hex": " ".join(f"{byte:02x}" for byte in header),
            "ascii": "".join(chr(byte) if 32 <= byte < 127 else "." for byte in header),
        },
        "trailer": {
            "offset": max(0, len(data) - len(trailer)),
            "hex": " ".join(f"{byte:02x}" for byte in trailer),
            "ascii": "".join(chr(byte) if 32 <= byte < 127 else "." for byte in trailer),
        },
        "rows": preview,
    }
