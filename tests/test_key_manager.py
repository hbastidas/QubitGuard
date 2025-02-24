import pytest
from QubitGuard.crypto_manager import CryptoManager, KeyManager

@pytest.fixture
def crypto_manager():
    return CryptoManager()

@pytest.fixture
def key_manager(crypto_manager):
    return KeyManager(crypto_manager)

def test_key_manager_initialization(key_manager):
    """Test KeyManager initialization"""
    assert key_manager.key_store == {}
    assert hasattr(key_manager, 'crypto_manager')

def test_generate_new_key_pair(key_manager):
    """Test key pair generation for a user"""
    user_id = "test_user"
    key_pair = key_manager.generate_new_key_pair(user_id)
    
    # Verify keys are stored for the user
    assert user_id in key_manager.key_store
    
    # Verify key pair structure
    assert isinstance(key_pair, tuple)
    assert len(key_pair) == 2
    
    # Verify both keys are bytes
    private_key, public_key = key_pair
    assert isinstance(private_key, bytes)
    assert isinstance(public_key, bytes)
    assert len(private_key) > 0
    assert len(public_key) > 0

def test_multiple_user_key_pairs(key_manager):
    """Test key generation for multiple users"""
    users = ["alice", "bob", "charlie"]
    user_keys = {}
    
    # Generate keys for each user
    for user in users:
        user_keys[user] = key_manager.generate_new_key_pair(user)
    
    # Verify each user has unique keys
    for i, user1 in enumerate(users):
        for j, user2 in enumerate(users):
            if i != j:
                # Compare public keys (second element of the tuple)
                assert user_keys[user1][1] != user_keys[user2][1]

def test_key_overwrite(key_manager):
    """Test key overwrite for existing user"""
    user_id = "test_user"
    
    # Generate initial keys
    initial_keys = key_manager.generate_new_key_pair(user_id)
    initial_public_key = initial_keys[1]  # Second element is public key
    
    # Generate new keys for same user
    new_keys = key_manager.generate_new_key_pair(user_id)
    new_public_key = new_keys[1]  # Second element is public key
    
    # Verify keys are different
    assert initial_public_key != new_public_key

def test_nonexistent_user(key_manager):
    """Test accessing keys for non-existent user"""
    with pytest.raises(KeyError):
        _ = key_manager.key_store["nonexistent_user"]
