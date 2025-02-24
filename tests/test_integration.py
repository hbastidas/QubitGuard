import os
import pytest
from click.testing import CliRunner
from QubitGuard.cli import cli

@pytest.fixture
def runner():
    return CliRunner()

def test_secure_communication_workflow(runner):
    """Test the complete secure communication workflow between Alice and Bob using post-quantum cryptography.
    
    This test demonstrates:
    1. Key generation (Kyber for encryption, Dilithium for signing)
    2. Public key exchange
    3. Secure message encryption and decryption
    4. Message signing and signature verification
    """
    with runner.isolated_filesystem() as fs:
        # Create directories for test files
        demo_dir = os.path.join(fs, 'demo')
        alice_keys_dir = os.path.join(demo_dir, 'alice_keys')
        bob_keys_dir = os.path.join(demo_dir, 'bob_keys')
        os.makedirs(alice_keys_dir)
        os.makedirs(bob_keys_dir)
        
        # Step 1: Generate Kyber and Dilithium keys for Alice and Bob
        alice_genkeys = runner.invoke(cli, ['genkeys', '--output-dir', alice_keys_dir])
        assert alice_genkeys.exit_code == 0
        assert "✅ Keys generated successfully" in alice_genkeys.output
        assert os.path.exists(os.path.join(alice_keys_dir, 'kyber_private_key.bin'))
        assert os.path.exists(os.path.join(alice_keys_dir, 'kyber_public_key.bin'))
        assert os.path.exists(os.path.join(alice_keys_dir, 'dilithium_private_key.bin'))
        assert os.path.exists(os.path.join(alice_keys_dir, 'dilithium_public_key.bin'))
        
        bob_genkeys = runner.invoke(cli, ['genkeys', '--output-dir', bob_keys_dir])
        assert bob_genkeys.exit_code == 0
        assert "✅ Keys generated successfully" in bob_genkeys.output
        assert os.path.exists(os.path.join(bob_keys_dir, 'kyber_private_key.bin'))
        assert os.path.exists(os.path.join(bob_keys_dir, 'kyber_public_key.bin'))
        assert os.path.exists(os.path.join(bob_keys_dir, 'dilithium_private_key.bin'))
        assert os.path.exists(os.path.join(bob_keys_dir, 'dilithium_public_key.bin'))

        # Step 2: Export public keys to JSON
        alice_public_json = os.path.join(demo_dir, 'alice_public.json')
        alice_export = runner.invoke(cli, ['export-keys', alice_public_json, '--key-dir', alice_keys_dir])
        assert alice_export.exit_code == 0
        assert os.path.exists(alice_public_json)
        assert "✅ Public keys exported" in alice_export.output

        bob_public_json = os.path.join(demo_dir, 'bob_public.json')
        bob_export = runner.invoke(cli, ['export-keys', bob_public_json, '--key-dir', bob_keys_dir])
        assert bob_export.exit_code == 0
        assert os.path.exists(bob_public_json)
        assert "✅ Public keys exported" in bob_export.output

        # Step 3: Alice sends an encrypted and signed message to Bob
        message = "Hello Bob! This is a secret message from Alice."
        encrypted_message = os.path.join(demo_dir, 'encrypted_message.bin')
        
        alice_encrypt = runner.invoke(cli, [
            'encrypt',
            message,
            '-k', os.path.join(bob_keys_dir, 'kyber_public_key.bin'),
            '-s', os.path.join(alice_keys_dir, 'dilithium_private_key.bin'),
            '-o', encrypted_message
        ])
        assert alice_encrypt.exit_code == 0
        assert os.path.exists(encrypted_message)
        assert "✅ Encrypted message saved" in alice_encrypt.output

        # Step 4: Bob decrypts and verifies Alice's message
        bob_decrypt = runner.invoke(cli, [
            'decrypt',
            encrypted_message,
            '-k', os.path.join(bob_keys_dir, 'kyber_private_key.bin'),
            '-s', os.path.join(alice_keys_dir, 'dilithium_public_key.bin')
        ])
        assert bob_decrypt.exit_code == 0
        assert "✅ Decrypted message:" in bob_decrypt.output
        assert message in bob_decrypt.output

        # Step 5: Bob sends an encrypted and signed reply to Alice
        reply = "Hi Alice! I received your message. Here's my secret reply."
        encrypted_reply = os.path.join(demo_dir, 'encrypted_reply.bin')
        
        bob_encrypt = runner.invoke(cli, [
            'encrypt',
            reply,
            '-k', os.path.join(alice_keys_dir, 'kyber_public_key.bin'),
            '-s', os.path.join(bob_keys_dir, 'dilithium_private_key.bin'),
            '-o', encrypted_reply
        ])
        assert bob_encrypt.exit_code == 0
        assert os.path.exists(encrypted_reply)
        assert "✅ Encrypted message saved" in bob_encrypt.output

        # Step 6: Alice decrypts and verifies Bob's reply
        alice_decrypt = runner.invoke(cli, [
            'decrypt',
            encrypted_reply,
            '-k', os.path.join(alice_keys_dir, 'kyber_private_key.bin'),
            '-s', os.path.join(bob_keys_dir, 'dilithium_public_key.bin')
        ])
        assert alice_decrypt.exit_code == 0
        assert "✅ Decrypted message:" in alice_decrypt.output
        assert reply in alice_decrypt.output

def test_error_handling(runner):
    """Test error handling in CLI commands"""
    with runner.isolated_filesystem() as fs:
        demo_dir = os.path.join(fs, 'demo')
        os.makedirs(demo_dir)

        # Test encryption with missing public key
        result = runner.invoke(cli, [
            'encrypt',
            'test message',
            '-k', os.path.join(demo_dir, 'nonexistent_kyber_public.bin'),
            '-s', os.path.join(demo_dir, 'nonexistent_dilithium_private.bin'),
            '-o', os.path.join(demo_dir, 'encrypted.bin')
        ])
        assert result.exit_code != 0
        
        # Test decryption with missing files
        result = runner.invoke(cli, [
            'decrypt',
            os.path.join(demo_dir, 'nonexistent.bin'),
            '-k', os.path.join(demo_dir, 'nonexistent_kyber_private.bin'),
            '-s', os.path.join(demo_dir, 'nonexistent_dilithium_public.bin')
        ])
        assert result.exit_code != 0

        # Test key generation with invalid directory
        result = runner.invoke(cli, [
            'genkeys',
            '--output-dir', '/nonexistent/directory'
        ])
        assert result.exit_code != 0

        # Test export-keys with missing key directory
        result = runner.invoke(cli, [
            'export-keys',
            os.path.join(demo_dir, 'public.json'),
            '--key-dir', os.path.join(demo_dir, 'nonexistent_keys')
        ])
        assert result.exit_code != 0
