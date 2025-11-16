"""Unit tests for WebSocket Transport."""

import pytest
import json
import base64
from unittest.mock import Mock, patch, AsyncMock

from platform_challenge_sdk.transport.ws import (
    AeadSession,
    verify_validator_quote,
)


class TestAeadSession:
    """Tests for AEAD session encryption/decryption."""

    def test_encrypt_decrypt(self):
        """Test that encryption and decryption work correctly."""
        key = b"0" * 32  # 32-byte key for ChaCha20-Poly1305
        session = AeadSession(key)

        original = {"type": "test", "data": "hello"}
        encrypted = session.encrypt(original)
        decrypted = session.decrypt(encrypted)

        assert decrypted == original
        assert "enc" in encrypted
        assert "nonce" in encrypted
        assert "ciphertext" in encrypted

    def test_encrypt_produces_different_output(self):
        """Test that encryption produces different output each time."""
        key = b"0" * 32
        session = AeadSession(key)

        original = {"type": "test", "data": "hello"}
        encrypted1 = session.encrypt(original)
        encrypted2 = session.encrypt(original)

        # Nonces should be different
        assert encrypted1["nonce"] != encrypted2["nonce"]
        # Ciphertexts should be different
        assert encrypted1["ciphertext"] != encrypted2["ciphertext"]

class TestVerifyValidatorQuote:
    """Tests for validator quote verification."""

    @pytest.mark.asyncio
    async def test_verify_validator_quote_missing_quote(self):
        """Test that missing quote fails validation."""
        result = await verify_validator_quote(
            val_quote_b64="",
            val_event_log=None,
            val_rtmrs=None,
            nonce=b"0" * 32,
            dev_mode=True,
            challenge_env_mode="dev",
        )

        assert result["valid"] is False
        assert "quote" in result.get("error", "").lower()

    @pytest.mark.asyncio
    async def test_verify_validator_quote_short_quote(self):
        """Test that short quote fails validation."""
        short_quote = base64.b64encode(b"0" * 100).decode("ascii")
        result = await verify_validator_quote(
            val_quote_b64=short_quote,
            val_event_log=None,
            val_rtmrs=None,
            nonce=b"0" * 32,
            dev_mode=True,
            challenge_env_mode="dev",
        )

        assert result["valid"] is False
        assert (
            "size" in result.get("error", "").lower() or "length" in result.get("error", "").lower()
        )

    @pytest.mark.asyncio
    async def test_verify_validator_quote_environment_mismatch(self):
        """Test that environment mismatch fails validation."""
        valid_quote = base64.b64encode(b"0" * 1024).decode("ascii")
        event_log = json.dumps({"environment_mode": "prod"})

        result = await verify_validator_quote(
            val_quote_b64=valid_quote,
            val_event_log=event_log,
            val_rtmrs=None,
            nonce=b"0" * 32,
            dev_mode=True,
            challenge_env_mode="dev",
        )

        assert result["valid"] is False
        assert "environment" in result.get("error", "").lower()

    @pytest.mark.asyncio
    async def test_verify_validator_quote_valid_structure_dev_mode(self):
        """Test that valid structure passes in dev mode."""
        valid_quote = base64.b64encode(b"0" * 1024).decode("ascii")
        event_log = json.dumps({"environment_mode": "dev"})

        result = await verify_validator_quote(
            val_quote_b64=valid_quote,
            val_event_log=event_log,
            val_rtmrs=None,
            nonce=b"0" * 32,
            dev_mode=True,
            challenge_env_mode="dev",
        )

        # In dev mode, valid structure should pass
        assert result["valid"] is True
