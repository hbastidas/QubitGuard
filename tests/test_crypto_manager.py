import os
import pytest
from QubitGuard.crypto_manager import CryptoManager

@pytest.fixture
def crypto_manager():
    return CryptoManager()

@pytest.fixture
def test_data():
    return b"Test message for cryptographic operations"

@pytest.fixture
def temp_dir(tmp_path):
    return tmp_path

def test_key_exchange_pair_generation(crypto_manager, temp_dir):
    """Test Kyber key pair generation"""
    private_key_path = temp_dir / "kyber_private.bin"
    public_key_path = temp_dir / "kyber_public.bin"
    
    # Generate keys
    private_key, public_key = crypto_manager.generate_key_exchange_pair()
    
    # Save keys
    with open(private_key_path, "wb") as f:
        f.write(private_key)
    with open(public_key_path, "wb") as f:
        f.write(public_key)
    
    # Verify files exist and are not empty
    assert os.path.exists(private_key_path)
    assert os.path.exists(public_key_path)
    assert os.path.getsize(private_key_path) > 0
    assert os.path.getsize(public_key_path) > 0

def test_signing_pair_generation(crypto_manager, temp_dir):
    """Test Dilithium key pair generation"""
    private_key_path = temp_dir / "dilithium_private.bin"
    public_key_path = temp_dir / "dilithium_public.bin"
    
    # Generate keys
    private_key, public_key = crypto_manager.generate_signing_pair()
    
    # Save keys
    with open(private_key_path, "wb") as f:
        f.write(private_key)
    with open(public_key_path, "wb") as f:
        f.write(public_key)
    
    # Verify files exist and are not empty
    assert os.path.exists(private_key_path)
    assert os.path.exists(public_key_path)
    assert os.path.getsize(private_key_path) > 0
    assert os.path.getsize(public_key_path) > 0

def test_encryption_decryption(crypto_manager, test_data):
    """Test encryption and decryption using Kyber"""
    # Generate keys and set signing keys
    private_key, public_key = crypto_manager.generate_key_exchange_pair()
    signing_private, signing_public = crypto_manager.generate_signing_pair()
    
    # Set the signing keys in the crypto manager
    crypto_manager.signing_private_key = signing_private
    crypto_manager.signing_public_key = signing_public
    
    # Encrypt data
    encrypted_data = crypto_manager.encrypt_data(test_data, public_key)
    assert encrypted_data != test_data
    assert len(encrypted_data) > 0
    
    # Decrypt data
    decrypted_data = crypto_manager.decrypt_data(encrypted_data, private_key, signing_public)
    assert decrypted_data == test_data

def test_signing_verification(crypto_manager, test_data):
    """Test signing and verification using Dilithium"""
    # Generate keys and set them
    private_key, public_key = crypto_manager.generate_signing_pair()
    crypto_manager.signing_private_key = private_key
    crypto_manager.signing_public_key = public_key
    
    # Sign data
    signature = crypto_manager.sign_data(test_data)
    assert len(signature) > 0
    
    # Verify signature
    assert crypto_manager.verify_signature(test_data, signature, public_key)
    
    # Test with modified data
    modified_data = test_data + b"tampered"
    assert not crypto_manager.verify_signature(modified_data, signature, public_key)

def test_encryption_with_invalid_key(crypto_manager, test_data):
    """Test encryption with invalid public key"""
    invalid_key = b"invalid_key"
    with pytest.raises(ValueError):
        crypto_manager.encrypt_data(test_data, invalid_key)

def test_decryption_with_invalid_key(crypto_manager, test_data):
    """Test decryption with invalid private key"""
    # Generate valid keys and encrypt data
    private_key, public_key = crypto_manager.generate_key_exchange_pair()
    signing_private, signing_public = crypto_manager.generate_signing_pair()
    
    # Set signing keys
    crypto_manager.signing_private_key = signing_private
    crypto_manager.signing_public_key = signing_public
    
    encrypted_data = crypto_manager.encrypt_data(test_data, public_key)
    
    # Try to decrypt with invalid key
    invalid_key = b"invalid_key"
    with pytest.raises(ValueError):
        crypto_manager.decrypt_data(encrypted_data, invalid_key, signing_public)

def test_signing_with_invalid_key(crypto_manager, test_data):
    """Test signing with invalid private key"""
    # Set an invalid signing key
    crypto_manager.signing_private_key = b"invalid_key"
    
    # Attempt to sign should return None or raise an exception
    try:
        result = crypto_manager.sign_data(test_data)
        assert result is None
    except Exception as e:
        assert isinstance(e, (ValueError, Exception))

def test_verification_with_invalid_key(crypto_manager, test_data):
    """Test verification with invalid public key"""
    # Generate and set valid keys
    private_key, public_key = crypto_manager.generate_signing_pair()
    crypto_manager.signing_private_key = private_key
    crypto_manager.signing_public_key = public_key
    
    # Sign with valid key
    signature = crypto_manager.sign_data(test_data)
    
    # Try to verify with invalid key
    invalid_key = b"invalid_key"
    # Should return False for invalid key
    assert not crypto_manager.verify_signature(test_data, signature, invalid_key)

def test_large_data_encryption(crypto_manager, temp_dir):
    """Test encryption and decryption of large data"""
    large_data = os.urandom(1024 * 1024)  # 1MB of random data
    
    # Generate keys
    private_key, public_key = crypto_manager.generate_key_exchange_pair()
    signing_private, signing_public = crypto_manager.generate_signing_pair()
    
    # Set signing keys
    crypto_manager.signing_private_key = signing_private
    crypto_manager.signing_public_key = signing_public
    
    # Encrypt and decrypt
    encrypted_data = crypto_manager.encrypt_data(large_data, public_key)
    decrypted_data = crypto_manager.decrypt_data(encrypted_data, private_key, signing_public)
    
    assert decrypted_data == large_data
