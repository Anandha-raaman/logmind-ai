import os
from pathlib import Path
from typing import Tuple
from config.settings import settings


class SecurityValidationError(ValueError):
    """Exception raised when security validation fails."""
    pass


def validate_file_path(file_path: str, allowed_dirs: list[str] = None) -> Path:
    """
    Validate path for safety, preventing path traversal attacks.
    """
    if not file_path:
        raise SecurityValidationError("File path cannot be empty.")
    
    path = Path(file_path).resolve()
    
    # Ensure file exists if checking existing file
    if not path.exists():
        raise SecurityValidationError(f"Path does not exist: {file_path}")
    
    if not path.is_file():
        raise SecurityValidationError(f"Target path is not a regular file: {file_path}")
    
    # Check allowed extensions
    if path.suffix.lower() not in settings.ALLOWED_EXTENSIONS:
        raise SecurityValidationError(
            f"Unsupported file extension '{path.suffix}'. Allowed extensions: {', '.join(settings.ALLOWED_EXTENSIONS)}"
        )
    
    # Check file size limit
    file_size = path.stat().st_size
    if file_size > settings.MAX_FILE_SIZE_BYTES:
        raise SecurityValidationError(
            f"File size ({file_size / (1024*1024):.2f} MB) exceeds maximum allowed limit ({settings.MAX_FILE_SIZE_MB} MB)."
        )
        
    return path


def validate_upload_content(filename: str, content_bytes: bytes) -> Tuple[bool, str]:
    """
    Validate uploaded file buffer size, extension, and character safety.
    """
    ext = Path(filename).suffix.lower()
    if ext not in settings.ALLOWED_EXTENSIONS:
        return False, f"Unsupported file format '{ext}'. Allowed formats: {', '.join(settings.ALLOWED_EXTENSIONS)}"
        
    if len(content_bytes) > settings.MAX_FILE_SIZE_BYTES:
        return False, f"File size exceeds maximum allowed limit of {settings.MAX_FILE_SIZE_MB} MB."
        
    # Check for binary control characters / non-text bytes
    try:
        sample = content_bytes[:4096].decode("utf-8", errors="replace")
        # Check null byte injection
        if "\x00" in sample:
            return False, "Binary or null-byte corrupted file content detected."
    except Exception as e:
        return False, f"File encoding validation failed: {str(e)}"
        
    return True, "Valid"
