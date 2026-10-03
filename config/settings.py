import os
from pathlib import Path
from typing import List
from dotenv import load_dotenv

# Load environment variables from .env file if available
load_dotenv()

BASE_DIR = Path(__file__).resolve().parent.parent

class Settings:
    PROJECT_NAME: str = "LogMind AI"
    VERSION: str = "1.0.0"
    ENVIRONMENT: str = os.getenv("LOGMIND_ENV", "development")
    
    # API Credentials
    GEMINI_API_KEY: str = os.getenv("GEMINI_API_KEY", "")
    
    # Storage
    DB_PATH: Path = BASE_DIR / os.getenv("LOGMIND_DB_PATH", "data/logmind.db")
    
    # Limits & Security
    MAX_FILE_SIZE_MB: int = int(os.getenv("LOGMIND_MAX_FILE_SIZE_MB", "50"))
    MAX_FILE_SIZE_BYTES: int = MAX_FILE_SIZE_MB * 1024 * 1024
    ALLOWED_EXTENSIONS: set = {".log", ".txt", ".json"}
    SECRET_REDACTION_ENABLED: bool = os.getenv("LOGMIND_SECRET_REDACTION_ENABLED", "true").lower() == "true"
    
    # Anomaly Detection Defaults
    DEFAULT_SPIKE_THRESHOLD_STD: float = float(os.getenv("LOGMIND_ANOMALY_SPIKE_THRESHOLD", "2.5"))
    DEFAULT_MIN_EVENTS_FOR_ANOMALY: int = int(os.getenv("LOGMIND_MIN_ANOMALY_EVENTS", "5"))
    DEFAULT_WINDOW_MINUTES: int = 5
    
    # Server configuration
    API_HOST: str = "127.0.0.1"
    API_PORT: int = 8000
    
    @property
    def is_gemini_configured(self) -> bool:
        """Return True if Gemini API key is configured non-empty."""
        return bool(self.GEMINI_API_KEY and self.GEMINI_API_KEY.strip() and not self.GEMINI_API_KEY.startswith("your_"))

settings = Settings()
