import pytest
from logmind.validators import validate_file_path, validate_upload_content, SecurityValidationError
from config.settings import settings


def test_validate_upload_content_valid():
    is_valid, msg = validate_upload_content("sample.log", b"2026-10-02 10:00:00 [INFO] test log line\n")
    assert is_valid is True
    assert msg == "Valid"


def test_validate_upload_content_unsupported_extension():
    is_valid, msg = validate_upload_content("malicious.exe", b"binary content")
    assert is_valid is False
    assert "Unsupported file format" in msg


def test_validate_upload_content_oversized():
    huge_bytes = b"A" * (settings.MAX_FILE_SIZE_BYTES + 100)
    is_valid, msg = validate_upload_content("huge.log", huge_bytes)
    assert is_valid is False
    assert "exceeds maximum allowed limit" in msg


def test_validate_upload_content_null_bytes():
    null_bytes = b"2026-10-02 \x00 null byte binary payload"
    is_valid, msg = validate_upload_content("bad.log", null_bytes)
    assert is_valid is False
    assert "null-byte" in msg.lower()


def test_validate_file_path_nonexistent():
    with pytest.raises(SecurityValidationError, match="Path does not exist"):
        validate_file_path("non_existent_file_path_12345.log")
