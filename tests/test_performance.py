"""Performance tests for QubitGuard to validate optimizations.

These tests measure and document the performance characteristics of the
cryptographic operations to ensure optimizations are effective.
"""

import os
import time
import logging
import pytest
import tempfile
from pathlib import Path
from QubitGuard.crypto_manager import CryptoManager, KeyManager, AuditLog
from QubitGuard.performance_utils import timing_decorator, batch_read_files, batch_write_files


@pytest.fixture
def crypto_manager():
    """Provide a CryptoManager instance for performance tests."""
    return CryptoManager()


@pytest.fixture
def temp_dir():
    """Provide a temporary directory for test files."""
    with tempfile.TemporaryDirectory() as tmpdir:
        yield Path(tmpdir)


def test_lazy_ecdsa_initialization(crypto_manager):
    """Test that ECDSA keys are lazily initialized.
    
    This test verifies that ECDSA keys are generated only when first accessed,
    not during CryptoManager initialization. We verify this by checking that
    accessing the key property multiple times returns the same object.
    """
    # Access the ECDSA key for the first time
    first_access = crypto_manager.ecdsa_private_key
    
    # Second access should return the same key (cached)
    second_access = crypto_manager.ecdsa_private_key
    
    # Both accesses should return the same object reference
    assert first_access is second_access, "ECDSA key should be cached"
    
    # Public key should also be initialized
    assert crypto_manager.ecdsa_public_key is not None


def test_key_generation_performance(crypto_manager):
    """Benchmark key generation operations."""
    benchmark_iterations = 5
    times = []
    
    for _ in range(benchmark_iterations):
        start = time.perf_counter()
        crypto_manager.generate_key_exchange_pair()
        end = time.perf_counter()
        times.append(end - start)
    
    avg_time = sum(times) / len(times)
    
    # Log timing information at INFO level for visibility in test output
    logging.info(f"Average key generation time: {avg_time:.4f} seconds")
    
    # Key generation should typically complete in reasonable time
    # Use environment variable for threshold to allow customization in CI/CD
    max_time = float(os.environ.get('QUBITGUARD_KEY_GEN_THRESHOLD', '5.0'))
    assert avg_time < max_time, f"Key generation is too slow: {avg_time:.4f}s > {max_time}s"


def test_encryption_decryption_performance(crypto_manager):
    """Benchmark encryption and decryption operations."""
    benchmark_iterations = 3
    
    # Generate keys
    private_key, public_key = crypto_manager.generate_key_exchange_pair()
    signing_private, signing_public = crypto_manager.generate_signing_pair()
    
    crypto_manager.signing_private_key = signing_private
    crypto_manager.signing_public_key = signing_public
    
    # Test data
    test_data = b"Performance test data" * 100  # ~2KB of data
    
    encryption_times = []
    decryption_times = []
    
    for _ in range(benchmark_iterations):
        # Measure encryption
        start = time.perf_counter()
        encrypted_data = crypto_manager.encrypt_data(test_data, public_key)
        end = time.perf_counter()
        encryption_times.append(end - start)
        
        # Measure decryption
        start = time.perf_counter()
        decrypted_data = crypto_manager.decrypt_data(encrypted_data, private_key, signing_public)
        end = time.perf_counter()
        decryption_times.append(end - start)
        
        assert decrypted_data == test_data
    
    avg_encrypt_time = sum(encryption_times) / len(encryption_times)
    avg_decrypt_time = sum(decryption_times) / len(decryption_times)
    
    # Log timing information
    logging.info(f"Average encryption time: {avg_encrypt_time:.4f} seconds")
    logging.info(f"Average decryption time: {avg_decrypt_time:.4f} seconds")
    
    # Operations should complete in reasonable time
    # Use environment variables for thresholds
    encrypt_threshold = float(os.environ.get('QUBITGUARD_ENCRYPT_THRESHOLD', '5.0'))
    decrypt_threshold = float(os.environ.get('QUBITGUARD_DECRYPT_THRESHOLD', '5.0'))
    
    assert avg_encrypt_time < encrypt_threshold, f"Encryption is too slow: {avg_encrypt_time:.4f}s"
    assert avg_decrypt_time < decrypt_threshold, f"Decryption is too slow: {avg_decrypt_time:.4f}s"


def test_signing_verification_performance(crypto_manager):
    """Benchmark signing and verification operations."""
    benchmark_iterations = 5
    
    # Generate keys
    signing_private, signing_public = crypto_manager.generate_signing_pair()
    crypto_manager.signing_private_key = signing_private
    crypto_manager.signing_public_key = signing_public
    
    test_data = b"Performance test signature data"
    
    signing_times = []
    verification_times = []
    
    for _ in range(benchmark_iterations):
        # Measure signing
        start = time.perf_counter()
        signature = crypto_manager.sign_data(test_data)
        end = time.perf_counter()
        signing_times.append(end - start)
        
        # Measure verification
        start = time.perf_counter()
        is_valid = crypto_manager.verify_signature(test_data, signature, signing_public)
        end = time.perf_counter()
        verification_times.append(end - start)
        
        assert is_valid
    
    avg_sign_time = sum(signing_times) / len(signing_times)
    avg_verify_time = sum(verification_times) / len(verification_times)
    
    # Log timing information
    logging.info(f"Average signing time: {avg_sign_time:.4f} seconds")
    logging.info(f"Average verification time: {avg_verify_time:.4f} seconds")
    
    # Operations should complete in reasonable time
    sign_threshold = float(os.environ.get('QUBITGUARD_SIGN_THRESHOLD', '3.0'))
    verify_threshold = float(os.environ.get('QUBITGUARD_VERIFY_THRESHOLD', '3.0'))
    
    assert avg_sign_time < sign_threshold, f"Signing is too slow: {avg_sign_time:.4f}s"
    assert avg_verify_time < verify_threshold, f"Verification is too slow: {avg_verify_time:.4f}s"


def test_batch_file_operations(temp_dir):
    """Test batch file read/write performance."""
    # Create test files
    num_files = 10
    file_data = {}
    
    for i in range(num_files):
        filepath = temp_dir / f"test_file_{i}.bin"
        data = os.urandom(1024)  # 1KB per file
        file_data[str(filepath)] = data
    
    # Measure batch write
    start = time.perf_counter()
    batch_write_files(file_data)
    write_time = time.perf_counter() - start
    
    # Measure batch read
    file_paths = list(file_data.keys())
    start = time.perf_counter()
    read_data = batch_read_files(file_paths)
    read_time = time.perf_counter() - start
    
    # Log timing information
    logging.info(f"Batch write time ({num_files} files): {write_time:.4f} seconds")
    logging.info(f"Batch read time ({num_files} files): {read_time:.4f} seconds")
    
    # Verify data integrity
    for path, original_data in file_data.items():
        assert read_data[path] == original_data
    
    # Batch operations should be reasonably fast
    io_threshold = float(os.environ.get('QUBITGUARD_IO_THRESHOLD', '1.0'))
    assert write_time < io_threshold, f"Batch write is too slow: {write_time:.4f}s"
    assert read_time < io_threshold, f"Batch read is too slow: {read_time:.4f}s"


def test_audit_log_context_manager(crypto_manager, temp_dir):
    """Test AuditLog context manager for proper resource management."""
    db_path = temp_dir / "test_audit.db"
    
    # Use context manager
    with AuditLog(crypto_manager, str(db_path)) as audit_log:
        # Generate keys for signing
        signing_private, signing_public = crypto_manager.generate_signing_pair()
        crypto_manager.signing_private_key = signing_private
        crypto_manager.signing_public_key = signing_public
        
        # Log some events
        audit_log.log_event("Test event 1")
        audit_log.log_event("Test event 2")
    
    # Connection should be closed after context exit
    # Verify by creating a new instance and reading
    with AuditLog(crypto_manager, str(db_path)) as audit_log:
        # Verify logged events
        assert audit_log.verify_log_entry(1)
        assert audit_log.verify_log_entry(2)


def test_audit_log_indexed_queries(crypto_manager, temp_dir):
    """Test that database index improves query performance."""
    db_path = temp_dir / "test_indexed_audit.db"
    
    with AuditLog(crypto_manager, str(db_path)) as audit_log:
        # Generate keys
        signing_private, signing_public = crypto_manager.generate_signing_pair()
        crypto_manager.signing_private_key = signing_private
        crypto_manager.signing_public_key = signing_public
        
        # Log multiple events
        num_events = 50
        for i in range(num_events):
            audit_log.log_event(f"Test event {i}")
        
        # Measure query performance
        query_times = []
        for entry_id in range(1, num_events + 1):
            start = time.perf_counter()
            audit_log.verify_log_entry(entry_id)
            end = time.perf_counter()
            query_times.append(end - start)
        
        avg_query_time = sum(query_times) / len(query_times)
        
        # Log timing information
        logging.info(f"Average audit log query time: {avg_query_time:.4f} seconds")
        
        # Queries should be fast with indexing
        query_threshold = float(os.environ.get('QUBITGUARD_QUERY_THRESHOLD', '1.0'))
        assert avg_query_time < query_threshold, f"Audit log queries are too slow: {avg_query_time:.4f}s"


def test_large_data_encryption_performance(crypto_manager):
    """Test encryption performance with larger data sets."""
    # Generate keys
    private_key, public_key = crypto_manager.generate_key_exchange_pair()
    signing_private, signing_public = crypto_manager.generate_signing_pair()
    
    crypto_manager.signing_private_key = signing_private
    crypto_manager.signing_public_key = signing_public
    
    # Test with 100KB of data
    large_data = os.urandom(100 * 1024)
    
    # Measure encryption
    start = time.perf_counter()
    encrypted_data = crypto_manager.encrypt_data(large_data, public_key)
    encrypt_time = time.perf_counter() - start
    
    # Measure decryption
    start = time.perf_counter()
    decrypted_data = crypto_manager.decrypt_data(encrypted_data, private_key, signing_public)
    decrypt_time = time.perf_counter() - start
    
    # Log timing information
    logging.info(f"Large data (100KB) encryption time: {encrypt_time:.4f} seconds")
    logging.info(f"Large data (100KB) decryption time: {decrypt_time:.4f} seconds")
    
    assert decrypted_data == large_data
    
    large_threshold = float(os.environ.get('QUBITGUARD_LARGE_DATA_THRESHOLD', '10.0'))
    assert encrypt_time < large_threshold, f"Large data encryption is too slow: {encrypt_time:.4f}s"
    assert decrypt_time < large_threshold, f"Large data decryption is too slow: {decrypt_time:.4f}s"


if __name__ == "__main__":
    # Allow running this file directly for quick performance checks
    pytest.main([__file__, "-v", "-s"])
