import re
from typing import Tuple

# Regex patterns for secret redaction
REDACTION_PATTERNS = [
    # Passwords in JSON / Key-Value / URL
    (re.compile(r'(?i)(password|passwd|pass|pwd|secret|token|api_key|apikey|access_token|auth_token)\s*[:=]\s*["\']?([^"\'\s,;&]+)["\']?'), r'\1="[REDACTED_SECRET]"'),
    # Bearer tokens
    (re.compile(r'(?i)bearer\s+[a-zA-Z0-9_\-\.=]+'), r'Bearer [REDACTED_TOKEN]'),
    # Basic auth / connection strings
    (re.compile(r'mongodb(\+srv)?://([^:]+):([^@]+)@'), r'mongodb\1://[REDACTED_USER]:[REDACTED_PASS]@'),
    (re.compile(r'postgres(ql)?://([^:]+):([^@]+)@'), r'postgres\1://[REDACTED_USER]:[REDACTED_PASS]@'),
    (re.compile(r'mysql://([^:]+):([^@]+)@'), r'mysql://[REDACTED_USER]:[REDACTED_PASS]@'),
    # AWS / Generic Keys
    (re.compile(r'(?i)(AKIA[0-9A-Z]{16})'), r'[REDACTED_AWS_KEY]'),
    (re.compile(r'(?i)(AIzaSy[a-zA-Z0-9_\-]{33})'), r'[REDACTED_GEMINI_KEY]'),
]

# Regex patterns for normalization (fingerprinting)
FINGERPRINT_PATTERNS = [
    # UUIDs
    (re.compile(r'[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}'), '[UUID]'),
    # Memory Addresses / Hex
    (re.compile(r'0x[0-9a-fA-F]+'), '[HEX]'),
    # IPv4 / IPv6
    (re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b'), '[IP]'),
    # Timestamps in message text (ISO 8601 or similar)
    (re.compile(r'\d{4}-\d{2}-\d{2}[T\s]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?'), '[TIMESTAMP]'),
    # Numeric IDs / sequence numbers (stand-alone numbers > 1 digit or after id=)
    (re.compile(r'\b(id|user_id|req_id|request_id|tx_id|order_id)=\d+'), r'\1=[ID]'),
    (re.compile(r'\b\d{4,}\b'), '[NUM]'),
    # Quoted arbitrary values that change per request
    (re.compile(r"'[^']+'"), "'[VALUE]'"),
]


def redact_secrets(text: str) -> str:
    """
    Apply best-effort secret redaction to log message text.
    """
    if not text:
        return ""
    
    redacted = text
    for pattern, replacement in REDACTION_PATTERNS:
        redacted = pattern.sub(replacement, redacted)
    return redacted


def normalize_log_message(message: str) -> str:
    """
    Normalize log message text for deterministic error grouping fingerprint calculation.
    """
    if not message:
        return ""
    
    # First redact secrets
    normalized = redact_secrets(message)
    
    # Replace volatile variables with placeholders
    for pattern, replacement in FINGERPRINT_PATTERNS:
        normalized = pattern.sub(replacement, normalized)
        
    # Standardize whitespace
    normalized = " ".join(normalized.split())
    return normalized
