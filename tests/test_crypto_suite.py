import os
import pytest
import tempfile
import sqlite3
import oqs
from pathlib import Path
from QubitGuard.crypto_manager import CryptoManager, KeyManager, AuditLog

@pytest.fixture
def crypto_manager():
    return CryptoManager()

@pytest.fixture
def key_manager(crypto_manager):
    return KeyManager(crypto_manager)

@pytest.fixture
def temp_db():
    # Create a temporary database for testing
    with tempfile.NamedTemporaryFile(suffix='.db', delete=False) as f:
        temp_db_path = f.name
    yield temp_db_path
    os.unlink(temp_db_path)

@pytest.fixture
def audit_log(crypto_manager, temp_db):
    audit_log = AuditLog(crypto_manager, temp_db)
    yield audit_log
    audit_log.close()

def test_crypto_manager_initialization(crypto_manager):
    """Test CryptoManager initialization and key generation"""
    # Test instance creation
    assert isinstance(crypto_manager, CryptoManager)
    
    # Test initial key state (should be None until generated)
    assert crypto_manager.signing_private_key is None
    assert crypto_manager.signing_public_key is None
    
    # Generate and set keys
    private_key, public_key = crypto_manager.generate_signing_pair()
    crypto_manager.signing_private_key = private_key
    crypto_manager.signing_public_key = public_key
    
    # Test key state after generation
    assert crypto_manager.signing_private_key is not None
    assert crypto_manager.signing_public_key is not None
    assert len(crypto_manager.signing_private_key) > 0
    assert len(crypto_manager.signing_public_key) > 0
    
    # Test algorithm selection
    assert crypto_manager.key_exchange_algorithm == 'Kyber512'
    assert crypto_manager.signature_algorithm == 'Dilithium3'

def test_key_exchange_pair_generation(crypto_manager):
    """Test generation of key exchange pairs"""
    secret_key, public_key = crypto_manager.generate_key_exchange_pair()
    
    assert secret_key is not None
    assert public_key is not None
    assert len(secret_key) > 0
    assert len(public_key) > 0

def test_key_manager_operations(key_manager):
    """Test KeyManager operations"""
    # Test key pair generation
    user_id = "test_user"
    key_manager.generate_new_key_pair(user_id)
    
    assert user_id in key_manager.key_store
    private_key, public_key = key_manager.key_store[user_id]
    assert private_key is not None
    assert public_key is not None
    
    # Test key retrieval
    retrieved_private, retrieved_public = key_manager.key_store[user_id]
    assert retrieved_private == private_key
    assert retrieved_public == public_key

def test_encryption_decryption_cycle(crypto_manager, key_manager):
    """Test full encryption and decryption cycle with signature verification"""
    # Generate and set signing keys
    signing_private, signing_public = crypto_manager.generate_signing_pair()
    crypto_manager.signing_private_key = signing_private
    crypto_manager.signing_public_key = signing_public
    
    # Prepare test data
    messages = [
        "Short message",
        "A longer message with special chars: !@#$%^&*()",
        "A very long message that spans\n"
        "multiple lines and contains various\n"
        "types of content including numbers: 12345\n"
        "and symbols: !@#$%^&*()_+-=[]{}|;:'\",.<>?/\\"
    ]
    
    # Generate encryption keys
    private_key, public_key = crypto_manager.generate_key_exchange_pair()
    
    for message in messages:
        # Test encryption
        message_bytes = message.encode()
        encrypted = crypto_manager.encrypt_data(message_bytes, public_key)
        assert encrypted is not None
        assert len(encrypted) > 0
        
        # Test decryption
        decrypted = crypto_manager.decrypt_data(encrypted, private_key, signing_public)
        assert decrypted is not None
        assert decrypted.decode() == message

def test_signature_operations(crypto_manager):
    """Test signature generation and verification"""
    # Generate and set signing keys
    signing_private, signing_public = crypto_manager.generate_signing_pair()
    crypto_manager.signing_private_key = signing_private
    crypto_manager.signing_public_key = signing_public
    
    test_data = b"Test message for signing"
    
    # Generate signature
    signature = crypto_manager.sign_data(test_data)
    assert signature is not None
    assert len(signature) > 0
    
    # Verify signature
    is_valid = crypto_manager.verify_signature(
        test_data,
        signature,
        signing_public
    )
    assert is_valid is True
    
    # Test invalid signature
    modified_data = b"Modified test message"
    is_valid = crypto_manager.verify_signature(
        modified_data,
        signature,
        signing_public
    )
    assert is_valid is False

def test_audit_log_operations(crypto_manager):
    """Test audit log operations including event logging and verification"""
    # Generate and set signing keys
    signing_private, signing_public = crypto_manager.generate_signing_pair()
    crypto_manager.signing_private_key = signing_private
    crypto_manager.signing_public_key = signing_public
    
    # Create temporary audit log
    with tempfile.NamedTemporaryFile(suffix='.db', delete=False) as f:
        temp_db_path = f.name
    
    audit_log = AuditLog(crypto_manager, temp_db_path)
    
    try:
        # Test event logging
        test_events = [
            "User login event",
            "Data encryption event",
            "Key generation event"
        ]
        
        for event in test_events:
            audit_log.log_event(event)
        
        # Verify each event's signature
        for entry_id in range(1, len(test_events) + 1):
            assert audit_log.verify_log_entry(entry_id) is True
    finally:
        audit_log.close()
        os.unlink(temp_db_path)

def test_error_handling(crypto_manager):
    """Test error handling in various scenarios"""
    # Generate and set signing keys
    signing_private, signing_public = crypto_manager.generate_signing_pair()
    crypto_manager.signing_private_key = signing_private
    crypto_manager.signing_public_key = signing_public
    
    # Generate encryption keys
    private_key, public_key = crypto_manager.generate_key_exchange_pair()
    message = b"Test message"
    
    # Test encryption with invalid public key
    invalid_key = b"invalid_key" * 10
    try:
        crypto_manager.encrypt_data(message, invalid_key)
        # If no exception is raised, the function should return None
        # or raise a ValueError
    except ValueError:
        pass  # Expected behavior
    
    # Test decryption with invalid private key
    encrypted = crypto_manager.encrypt_data(message, public_key)
    try:
        crypto_manager.decrypt_data(
            encrypted,
            invalid_key,
            signing_public
        )
        # If no exception is raised, the function should return None
        # or raise a ValueError
    except ValueError:
        pass  # Expected behavior
    
    # Test signature verification with invalid public key
    signature = crypto_manager.sign_data(message)
    is_valid = crypto_manager.verify_signature(
        message,
        signature,
        invalid_key
    )
    assert is_valid is False

def test_bidirectional_communication():
    """Test bidirectional secure communication between Alice and Bob.
    
    This test simulates a complete communication scenario where:
    1. Alice and Bob each have their own CryptoManager instances
    2. They exchange public keys for both encryption and signing
    3. They send encrypted and signed messages to each other
    4. They verify and decrypt received messages
    
    The test ensures that:
    - Messages can be sent securely in both directions
    - Signatures are properly verified
    - Messages maintain confidentiality and integrity
    - The communication is quantum-resistant
    """
    # Initialize Alice and Bob's crypto managers
    alice_crypto = CryptoManager()
    bob_crypto = CryptoManager()
    
    # Generate signing keys for both parties
    alice_signing_private, alice_signing_public = alice_crypto.generate_signing_pair()
    bob_signing_private, bob_signing_public = bob_crypto.generate_signing_pair()
    
    # Set signing keys
    alice_crypto.signing_private_key = alice_signing_private
    alice_crypto.signing_public_key = alice_signing_public
    bob_crypto.signing_private_key = bob_signing_private
    bob_crypto.signing_public_key = bob_signing_public
    
    # Generate encryption keys for both parties
    alice_private, alice_public = alice_crypto.generate_key_exchange_pair()
    bob_private, bob_public = bob_crypto.generate_key_exchange_pair()
    
    # Alice sends a message to Bob
    alice_message = b"Hello Bob! This is a secret message from Alice."
    alice_encrypted = alice_crypto.encrypt_data(alice_message, bob_public)
    
    # Bob decrypts and verifies Alice's message
    bob_decrypted = bob_crypto.decrypt_data(
        alice_encrypted,
        bob_private,
        alice_signing_public
    )
    assert bob_decrypted == alice_message
    
    # Bob sends a response to Alice
    bob_message = b"Hi Alice! I received your message. Here's my secret response."
    bob_encrypted = bob_crypto.encrypt_data(bob_message, alice_public)
    
    # Alice decrypts and verifies Bob's response
    alice_decrypted = alice_crypto.decrypt_data(
        bob_encrypted,
        alice_private,
        bob_signing_public
    )
    assert alice_decrypted == bob_message
    
    # Test multiple message exchange
    messages = [
        b"Message 1: How are you?",
        b"Message 2: I'm doing great!",
        b"Message 3: Let's meet tomorrow",
        b"Message 4: Sounds good!"
    ]
    
    # Simulate a conversation with multiple messages
    for i, msg in enumerate(messages):
        # Even messages are from Alice to Bob
        if i % 2 == 0:
            encrypted = alice_crypto.encrypt_data(msg, bob_public)
            decrypted = bob_crypto.decrypt_data(
                encrypted,
                bob_private,
                alice_signing_public
            )
        # Odd messages are from Bob to Alice
        else:
            encrypted = bob_crypto.encrypt_data(msg, alice_public)
            decrypted = alice_crypto.decrypt_data(
                encrypted,
                alice_private,
                bob_signing_public
            )
        assert decrypted == msg
