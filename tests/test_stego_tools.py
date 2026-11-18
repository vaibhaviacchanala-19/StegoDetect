import io
from pathlib import Path

from PIL import Image

from modules.tool_manager import analyze_all_tools, tool_status


def _write_png(path: Path, payload: bytes = b""):
    image = Image.new("RGB", (12, 12), color="purple")
    image.save(path, format="PNG")
    if payload:
        with open(path, "ab") as handle:
            handle.write(payload)


def _write_jpeg(path: Path, payload: bytes = b""):
    image = Image.new("RGB", (12, 12), color="teal")
    buffer = io.BytesIO()
    image.save(buffer, format="JPEG")
    data = buffer.getvalue()
    with open(path, "wb") as handle:
        handle.write(data)
    if payload:
        with open(path, "ab") as handle:
            handle.write(payload)


def _write_wav(path: Path):
    with open(path, "wb") as handle:
        handle.write(b"RIFF" + b"\x00\x00\x00\x00WAVEfmt " + b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00")


def test_stego_tool_suite_handles_synthetic_samples(tmp_path):
    png_path = tmp_path / "normal.png"
    jpeg_path = tmp_path / "normal.jpg"
    appended_png = tmp_path / "appended_payload.png"
    appended_jpeg = tmp_path / "appended_payload.jpg"
    wav_path = tmp_path / "sample.wav"
    corrupted = tmp_path / "corrupt.png"

    _write_png(png_path)
    _write_jpeg(jpeg_path)
    _write_png(appended_png, b"PK\x03\x04fake_zip_payload")
    _write_jpeg(appended_jpeg, b"PK\x03\x04fake_zip_payload")
    _write_wav(wav_path)
    corrupted.write_bytes(b"not-a-real-png")

    for file_path in [png_path, jpeg_path, appended_png, appended_jpeg, wav_path, corrupted]:
        result = analyze_all_tools(str(file_path))
        assert set(result["tools"].keys()) == {"steghide", "zsteg", "binwalk", "pngcheck", "exiftool"}
        assert result["analysis_summary"]
        for tool_result in result["tools"].values():
            assert "tool_name" in tool_result
            assert "findings" in tool_result
            assert isinstance(tool_result["findings"], list)
            assert "supported_formats" in tool_result


def test_tool_availability_reports_installation_recommendations(tmp_path):
    file_path = tmp_path / "sample.png"
    _write_png(file_path)

    result = analyze_all_tools(str(file_path))
    for tool_result in result["tools"].values():
        if tool_result["status"] == "unavailable":
            assert tool_result["install_recommendation"]
            assert tool_result["findings"]


def test_exiftool_is_detected_even_without_path_refresh():
    status = tool_status("exiftool")
    assert status["available"] is True
    assert status["path"]
