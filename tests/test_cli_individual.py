import os
import json
import pytest
from click.testing import CliRunner
from QubitGuard.cli import cli

@pytest.fixture
def runner():
    return CliRunner()

def test_genkeys_command(runner):
    """Test the genkeys command individually"""
    with runner.isolated_filesystem() as fs:
        output_dir = os.path.join(fs, 'keys')
        os.makedirs(output_dir)
        
        # Test successful key generation
        result = runner.invoke(cli, ['genkeys', '--output-dir', output_dir])
        assert result.exit_code == 0
        assert "✅ Keys generated successfully" in result.output
        
        # Verify all key files are created
        assert os.path.exists(os.path.join(output_dir, 'kyber_private_key.bin'))
        assert os.path.exists(os.path.join(output_dir, 'kyber_public_key.bin'))
        assert os.path.exists(os.path.join(output_dir, 'dilithium_private_key.bin'))
        assert os.path.exists(os.path.join(output_dir, 'dilithium_public_key.bin'))
        
        # Test with invalid directory
        result = runner.invoke(cli, ['genkeys', '--output-dir', '/nonexistent'])
        assert result.exit_code != 0

def test_export_keys_command(runner):
    """Test the export-keys command individually"""
    with runner.isolated_filesystem() as fs:
        # First generate keys
        keys_dir = os.path.join(fs, 'keys')
        os.makedirs(keys_dir)
        runner.invoke(cli, ['genkeys', '--output-dir', keys_dir])
        
        # Test key export
        export_file = os.path.join(fs, 'public_keys.json')
        result = runner.invoke(cli, ['export-keys', export_file, '--key-dir', keys_dir])
        assert result.exit_code == 0
        assert "✅ Public keys exported" in result.output
        
        # Verify JSON structure
        with open(export_file) as f:
            data = json.load(f)
            assert 'public_key' in data
            assert 'owner' in data
            assert 'created_at' in data
            assert isinstance(data['public_key'], str)
            assert isinstance(data['owner'], str)
            assert isinstance(data['created_at'], str)
        
        # Test with invalid key directory
        result = runner.invoke(cli, ['export-keys', export_file, '--key-dir', '/nonexistent'])
        assert result.exit_code != 0

def test_encrypt_command(runner):
    """Test the encrypt command individually"""
    with runner.isolated_filesystem() as fs:
        # Setup: Generate keys
        keys_dir = os.path.join(fs, 'keys')
        os.makedirs(keys_dir)
        runner.invoke(cli, ['genkeys', '--output-dir', keys_dir])
        
        # Test encryption
        message = "Test message"
        output_file = os.path.join(fs, 'encrypted.bin')
        result = runner.invoke(cli, [
            'encrypt',
            message,
            '-k', os.path.join(keys_dir, 'kyber_public_key.bin'),
            '-s', os.path.join(keys_dir, 'dilithium_private_key.bin'),
            '-o', output_file
        ])
        assert result.exit_code == 0
        assert "✅ Encrypted message saved" in result.output
        assert os.path.exists(output_file)
        
        # Test with missing key file
        result = runner.invoke(cli, [
            'encrypt',
            message,
            '-k', 'nonexistent.bin',
            '-s', os.path.join(keys_dir, 'dilithium_private_key.bin'),
            '-o', output_file
        ])
        assert result.exit_code != 0

def test_decrypt_command(runner):
    """Test the decrypt command individually"""
    with runner.isolated_filesystem() as fs:
        # Setup: Generate keys and create encrypted message
        keys_dir = os.path.join(fs, 'keys')
        os.makedirs(keys_dir)
        runner.invoke(cli, ['genkeys', '--output-dir', keys_dir])
        
        message = "Test message"
        encrypted_file = os.path.join(fs, 'encrypted.bin')
        
        # Create encrypted message
        runner.invoke(cli, [
            'encrypt',
            message,
            '-k', os.path.join(keys_dir, 'kyber_public_key.bin'),
            '-s', os.path.join(keys_dir, 'dilithium_private_key.bin'),
            '-o', encrypted_file
        ])
        
        # Test decryption
        result = runner.invoke(cli, [
            'decrypt',
            encrypted_file,
            '-k', os.path.join(keys_dir, 'kyber_private_key.bin'),
            '-s', os.path.join(keys_dir, 'dilithium_public_key.bin')
        ])
        assert result.exit_code == 0
        assert "✅ Decrypted message:" in result.output
        assert message in result.output
        
        # Test with invalid encrypted file
        result = runner.invoke(cli, [
            'decrypt',
            'nonexistent.bin',
            '-k', os.path.join(keys_dir, 'kyber_private_key.bin'),
            '-s', os.path.join(keys_dir, 'dilithium_public_key.bin')
        ])
        assert result.exit_code != 0

def test_command_help_messages(runner):
    """Test that all commands have proper help messages"""
    commands = ['genkeys', 'export-keys', 'encrypt', 'decrypt']
    
    for cmd in commands:
        result = runner.invoke(cli, [cmd, '--help'])
        assert result.exit_code == 0
        assert 'Usage:' in result.output
        assert 'Options:' in result.output
