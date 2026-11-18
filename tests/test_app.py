import io
import os

import pytest
from PIL import Image

from app import app
from database.db import clear_investigations


@pytest.fixture
def client():
    app.config["TESTING"] = True
    app.config["UPLOAD_FOLDER"] = os.path.join(os.getcwd(), "uploads")
    app.config["MAX_CONTENT_LENGTH"] = 25 * 1024 * 1024
    clear_investigations()
    with app.test_client() as client:
        yield client


def _make_png_bytes():
    image = Image.new("RGB", (8, 8), color="red")
    buffer = io.BytesIO()
    image.save(buffer, format="PNG")
    return buffer.getvalue()


def _make_jpeg_bytes():
    image = Image.new("RGB", (8, 8), color="blue")
    buffer = io.BytesIO()
    image.save(buffer, format="JPEG")
    return buffer.getvalue()


def test_valid_png_upload(client):
    response = client.post(
        "/upload",
        data={"file": (io.BytesIO(_make_png_bytes()), "valid.png")},
        content_type="multipart/form-data",
    )
    assert response.status_code == 200
    assert b"valid.png" in response.data


def test_valid_jpeg_upload(client):
    response = client.post(
        "/upload",
        data={"file": (io.BytesIO(_make_jpeg_bytes()), "valid.jpeg")},
        content_type="multipart/form-data",
    )
    assert response.status_code == 200
    assert b"valid.jpeg" in response.data


def test_invalid_file_upload(client):
    response = client.post(
        "/upload",
        data={"file": (io.BytesIO(b"not a real file"), "bad.txt")},
        content_type="multipart/form-data",
    )
    assert response.status_code == 200
    assert b"Invalid file type" in response.data or b"Unable to classify" in response.data


def test_oversized_file_upload(client):
    large_data = b"A" * (25 * 1024 * 1024 + 1)
    response = client.post(
        "/upload",
        data={"file": (io.BytesIO(large_data), "large.bin")},
        content_type="multipart/form-data",
    )
    assert response.status_code == 200
    assert b"too large" in response.data.lower() or b"size" in response.data.lower()


def test_extension_mismatch_detected(client):
    response = client.post(
        "/upload",
        data={"file": (io.BytesIO(_make_png_bytes()), "fake.jpg")},
        content_type="multipart/form-data",
    )
    assert response.status_code == 200
    assert b"extension mismatch" in response.data.lower() or b"mismatch" in response.data.lower()


def test_duplicate_upload(client):
    data = _make_png_bytes()
    response = client.post(
        "/upload",
        data={"file": (io.BytesIO(data), "dup.png")},
        content_type="multipart/form-data",
    )
    second = client.post(
        "/upload",
        data={"file": (io.BytesIO(data), "dup.png")},
        content_type="multipart/form-data",
    )
    assert response.status_code == 200
    assert second.status_code == 200
    assert b"duplicate" in second.data.lower()


def test_corrupted_image_upload(client):
    response = client.post(
        "/upload",
        data={"file": (io.BytesIO(b"\x89PNG\r\n\x1a\nnot-valid"), "broken.png")},
        content_type="multipart/form-data",
    )
    assert response.status_code == 200
    assert b"invalid" in response.data.lower() or b"corrupt" in response.data.lower() or b"unable to classify" in response.data.lower()


if __name__ == "__main__":
    pytest.main(["-q", "tests/test_app.py"])
