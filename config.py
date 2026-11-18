import os

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
UPLOAD_FOLDER = os.path.join(BASE_DIR, "uploads")
REPORTS_FOLDER = os.path.join(BASE_DIR, "reports")
DATABASE_PATH = os.path.join(BASE_DIR, "database", "stegodetect.db")
ALLOWED_EXTENSIONS = {
    "jpg", "jpeg", "png", "bmp", "gif", "tif", "tiff", "wav", "au", "aiff",
    "pdf", "zip", "bin", "exe"
}
MAX_FILE_SIZE = 25 * 1024 * 1024
MAX_CONTENT_LENGTH = MAX_FILE_SIZE
SECRET_KEY = "dev-secret-key-change-me"
