import hashlib
import os
from datetime import datetime, timezone
from pathlib import Path

from PIL import Image
from werkzeug.utils import secure_filename

from config import ALLOWED_EXTENSIONS, MAX_FILE_SIZE, UPLOAD_FOLDER
from database.db import sha256_exists

MAGIC_SIGNATURES = {
    "png": (b"\x89PNG\r\n\x1a\n",),
    "jpeg": (b"\xff\xd8\xff",),
    "gif": (b"GIF87a", b"GIF89a"),
    "bmp": (b"BM",),
    "tiff": (b"II*\x00", b"MM\x00*"),
    "wav": (b"RIFF",),
    "au": (b".snd",),
    "aiff": (b"FORM",),
    "pdf": (b"%PDF",),
    "zip": (b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08"),
    "exe": (b"MZ",),
}

MIME_TYPES = {
    "png": "image/png",
    "jpeg": "image/jpeg",
    "jpg": "image/jpeg",
    "gif": "image/gif",
    "bmp": "image/bmp",
    "tiff": "image/tiff",
    "wav": "audio/wav",
    "au": "audio/basic",
    "aiff": "audio/aiff",
    "pdf": "application/pdf",
    "zip": "application/zip",
    "bin": "application/octet-stream",
    "exe": "application/x-msdownload",
}


def detect_file_type_from_signature(file_bytes):
    for actual_type, signatures in MAGIC_SIGNATURES.items():
        for signature in signatures:
            if signature in file_bytes[:64]:
                if actual_type == "wav":
                    if len(file_bytes) >= 12 and file_bytes[8:12] == b"WAVE":
                        return "wav"
                    continue
                if actual_type == "aiff":
                    if len(file_bytes) >= 8 and file_bytes[8:12] == b"AIFF":
                        return "aiff"
                    continue
                return actual_type
    return None


def compute_sha256(file_bytes):
    return hashlib.sha256(file_bytes).hexdigest()


def detect_mime_type(filename, actual_type=None):
    guessed = None
    if actual_type:
        guessed = MIME_TYPES.get(actual_type)
    if guessed:
        return guessed
    ext = Path(filename).suffix.lower().lstrip(".")
    guessed = MIME_TYPES.get(ext)
    return guessed or "application/octet-stream"


def detect_duplicate_hash(sha256_value):
    return sha256_exists(sha256_value)


def validate_image_integrity(file_bytes):
    try:
        with Image.open(__import__('io').BytesIO(file_bytes)) as image:
            image.verify()
        return True, None
    except Exception as exc:  # pragma: no cover - defensive
        return False, str(exc)


def build_safe_filename(original_name):
    safe_name = secure_filename(original_name)
    if not safe_name:
        safe_name = "uploaded_file.bin"
    return safe_name


def analyze_file(file_obj):
    if file_obj is None or not getattr(file_obj, "filename", None):
        return {"status": "error", "message": "No file was uploaded."}

    original_name = file_obj.filename
    safe_name = build_safe_filename(original_name)
    extension = Path(safe_name).suffix.lower().lstrip(".")

    if not extension or extension not in ALLOWED_EXTENSIONS:
        return {
            "status": "error",
            "message": "Invalid file type. Allowed types: JPEG, PNG, GIF, TIFF, WAV, PDF, ZIP, EXE, and more.",
        }

    file_bytes = file_obj.read()
    if not file_bytes:
        return {"status": "error", "message": "The uploaded file is empty."}

    if len(file_bytes) > MAX_FILE_SIZE:
        return {
            "status": "error",
            "message": f"File is too large. Maximum allowed size is {MAX_FILE_SIZE / (1024 * 1024):.0f} MB.",
        }

    actual_type = detect_file_type_from_signature(file_bytes)
    mime_type = detect_mime_type(safe_name, actual_type)

    if actual_type is None and extension not in {"bin"}:
        return {
            "status": "error",
            "message": "Unable to classify file signature. The file may be corrupted or not a supported format.",
        }

    if actual_type and extension and actual_type != extension and not (extension == "jpg" and actual_type == "jpeg"):
        mismatch_detected = True
    else:
        mismatch_detected = False

    if actual_type in {"png", "jpeg", "gif", "bmp", "tiff"}:
        valid_image, image_error = validate_image_integrity(file_bytes)
        if not valid_image:
            return {
                "status": "error",
                "message": f"The image file appears corrupted or invalid: {image_error}",
            }

    sha256_value = compute_sha256(file_bytes)
    if detect_duplicate_hash(sha256_value):
        return {
            "status": "duplicate",
            "message": "A duplicate file with the same SHA-256 hash has already been uploaded.",
            "sha256": sha256_value,
            "filename": safe_name,
        }

    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")
    stored_name = f"{timestamp}_{safe_name}"
    stored_path = os.path.join(UPLOAD_FOLDER, stored_name)
    with open(stored_path, "wb") as handle:
        handle.write(file_bytes)

    return {
        "status": "success" if not mismatch_detected else "warning",
        "message": "File uploaded and analyzed successfully." if not mismatch_detected else "Extension mismatch detected.",
        "filename": safe_name,
        "stored_filename": stored_name,
        "stored_path": stored_path,
        "actual_type": actual_type or extension,
        "mime_type": mime_type,
        "file_size": len(file_bytes),
        "sha256": sha256_value,
        "file_extension": extension,
        "creation_timestamp": datetime.fromtimestamp(os.path.getctime(stored_path)).strftime("%Y-%m-%d %H:%M:%S"),
        "modification_timestamp": datetime.fromtimestamp(os.path.getmtime(stored_path)).strftime("%Y-%m-%d %H:%M:%S"),
        "mismatch_detected": mismatch_detected,
    }
