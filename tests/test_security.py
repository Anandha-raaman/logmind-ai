import pytest
from logmind.normalizer import redact_secrets, normalize_log_message


def test_redact_secrets_passwords():
    raw = 'User login failed password="super_secret_password_123" for user="dev"'
    redacted = redact_secrets(raw)
    assert "super_secret_password_123" not in redacted
    assert "[REDACTED_SECRET]" in redacted


def test_redact_secrets_bearer_tokens():
    raw = "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.token"
    redacted = redact_secrets(raw)
    assert "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.token" not in redacted
    assert "Bearer [REDACTED_TOKEN]" in redacted


def test_redact_secrets_connection_strings():
    raw = "Failed connection to mongodb://admin_user:secret_pass_88@cluster0.mongodb.net/prod"
    redacted = redact_secrets(raw)
    assert "secret_pass_88" not in redacted
    assert "mongodb://[REDACTED_USER]:[REDACTED_PASS]@" in redacted


def test_redact_secrets_aws_keys():
    raw = "AWS access key AKIAIOSFODNN7EXAMPLE used in upload"
    redacted = redact_secrets(raw)
    assert "AKIAIOSFODNN7EXAMPLE" not in redacted
    assert "[REDACTED_AWS_KEY]" in redacted


def test_normalize_log_message():
    msg1 = "User ID 99482 connected from 192.168.1.104 at 2026-10-02T14:00:00Z"
    msg2 = "User ID 11029 connected from 10.0.0.1 at 2026-10-02T15:00:00Z"
    norm1 = normalize_log_message(msg1)
    norm2 = normalize_log_message(msg2)
    assert norm1 == norm2
    assert "[IP]" in norm1
