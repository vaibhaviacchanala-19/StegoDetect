import base64
import io
from pathlib import Path

from PIL import Image

from modules.base64_analyzer import analyze_base64
from modules.entropy_analyzer import analyze_entropy
from modules.image_analyzer import analyze_image
from modules.signature_analyzer import analyze_signature
from modules.strings_analyzer import analyze_strings


def _write_png(path: Path, payload: bytes = b""):
    image = Image.new("RGB", (16, 16), color="red")
    image.save(path, format="PNG")
    if payload:
        with open(path, "ab") as handle:
            handle.write(payload)


def _write_jpeg(path: Path):
    image = Image.new("RGB", (16, 16), color="blue")
    buffer = io.BytesIO()
    image.save(buffer, format="JPEG")
    path.write_bytes(buffer.getvalue())


def _write_lsb_image(path: Path):
    image = Image.new("RGB", (16, 16), color=(255, 255, 255))
    pixels = list(image.getdata())
    for index, pixel in enumerate(pixels):
        if index % 2 == 0:
            pixels[index] = (pixel[0] ^ 1, pixel[1], pixel[2])
    image.putdata(pixels)
    image.save(path, format="PNG")


def test_strings_analysis_detects_urls_and_commands(tmp_path):
    suspicious = tmp_path / "strings_sample.bin"
    payload = b"http://evil.example/malware.exe\ncmd.exe /c powershell -enc aGVsbG8=\n"
    suspicious.write_bytes(payload)
    result = analyze_strings(str(suspicious))
    assert result["available"] is True
    assert result["findings"]
    categories = {item["category"] for item in result["findings"]}
    assert categories.intersection({"url", "powershell", "cmd", "executable_reference"})


def test_base64_analysis_detects_payloads(tmp_path):
    file_path = tmp_path / "b64_sample.bin"
    encoded = base64.b64encode(b"forensic payload")
    file_path.write_bytes(encoded + b"\nhttp://example.com\n")
    result = analyze_base64(str(file_path))
    assert result["status"] in {"ok", "no_findings"}
    assert any(item["decoded_output"] == "forensic payload" for item in result["results"])


def test_entropy_analysis_reports_sections_and_summary(tmp_path):
    file_path = tmp_path / "entropy.bin"
    file_path.write_bytes((b"\x00\x01\x02\x03\x04\x05\x06\x07" * 128) + b"\x90\x90\x90\x90\x90")
    result = analyze_entropy(str(file_path))
    assert "overall_entropy" in result
    assert result["section_entropies"]
    assert result["summary"]


def test_signature_analysis_reports_extension_mismatch(tmp_path):
    png_path = tmp_path / "mismatch.jpg"
    _write_png(png_path)
    result = analyze_signature(str(png_path))
    assert result["actual_type"] == "png"
    assert any(item["finding_name"] == "Extension mismatch" for item in result["findings"])


def test_signature_analysis_detects_appended_payload(tmp_path):
    png_path = tmp_path / "appended.png"
    _write_png(png_path, b"PK\x03\x04zip_payload")
    result = analyze_signature(str(png_path))
    assert any("appended" in item["finding_name"].lower() for item in result["findings"])


def test_image_analysis_handles_lsb_modified_file(tmp_path):
    image_path = tmp_path / "lsb.png"
    _write_lsb_image(image_path)
    result = analyze_image(str(image_path))
    assert result["available"] is True
    assert result["dimensions"]["width"] == 16
    assert result["lsb_summary"]["odd_lsb_count"] >= 0
