"""Tests for secret and credential redaction."""

from log_detective.security import redact_secrets


def test_redact_bearer_token():
    log = "2026-10-20 [INFO] Request header Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.e30"
    redacted = redact_secrets(log)
    assert "[REDACTED_TOKEN]" in redacted
    assert "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9" not in redacted


def test_redact_api_keys():
    openai_key = "2026-10-20 [ERROR] Failed call with key sk-1234567890abcdef1234567890"
    redacted = redact_secrets(openai_key)
    assert "[REDACTED_API_KEY]" in redacted
    assert "sk-1234567890abcdef1234567890" not in redacted

    google_key = "2026-10-20 [ERROR] AIzaSyD1234567890abcdefghijklmnopqrstuv"
    assert "[REDACTED_GOOGLE_API_KEY]" in redact_secrets(google_key)


def test_redact_passwords_and_connections():
    db_log = "Connecting to postgres://admin:super_secret_password_123@db.internal:5432/store"
    redacted = redact_secrets(db_log)
    assert "[REDACTED_PASSWORD]" in redacted
    assert "super_secret_password_123" not in redacted

    json_pwd = '{"user": "alice", "password": "MySuperSecretPassword123!"}'
    redacted_json = redact_secrets(json_pwd)
    assert "[REDACTED_PASSWORD]" in redacted_json
    assert "MySuperSecretPassword123!" not in redacted_json


def test_redact_aws_credentials():
    aws_log = "AWS access key: AKIAIOSFODNN7EXAMPLE and secret aws_secret_access_key='wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'"
    redacted = redact_secrets(aws_log)
    assert "[REDACTED_AWS_KEY]" in redacted
    assert "[REDACTED_AWS_SECRET]" in redacted
    assert "AKIAIOSFODNN7EXAMPLE" not in redacted
