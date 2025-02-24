"""Common test fixtures and configurations for QubitGuard tests."""

import pytest
from QubitGuard.crypto_manager import CryptoManager, KeyManager, AuditLog

@pytest.fixture
def crypto_manager():
    """Provide a fresh CryptoManager instance for each test."""
    return CryptoManager()

@pytest.fixture
def key_manager(crypto_manager):
    """Provide a KeyManager instance with a CryptoManager."""
    return KeyManager(crypto_manager)

@pytest.fixture
def audit_log(crypto_manager, tmp_path):
    """Provide an AuditLog instance with a temporary database."""
    db_path = tmp_path / "test_audit.db"
    return AuditLog(crypto_manager, str(db_path))
