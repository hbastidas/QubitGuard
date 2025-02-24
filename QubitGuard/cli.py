"""
CLI commands for QubitGuard operations.

This module provides command-line interface for:
- Key generation (public/private)
- Message encryption
- Message decryption
- Signature verification
"""

import click
import base64
import json
import datetime
from pathlib import Path
from .crypto_manager import CryptoManager


@click.group()
def cli():
    """QubitGuard CLI - Post-quantum cryptographic tools."""
    pass

@cli.command()
@click.option('--output-dir', '-o', default='.',
              help='Directory to store the generated keys')
def genkeys(output_dir):
    """Generate a post-quantum key pair (public/private)."""
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    # Create a new CryptoManager instance
    crypto_manager = CryptoManager()
    
    # Generate key exchange pair
    secret_key, public_key = crypto_manager.generate_key_exchange_pair()
    
    # Generate signing pair
    signing_private_key, signing_public_key = crypto_manager.generate_signing_pair()
    
    # Save Kyber keys for encryption
    with open(output_dir / 'kyber_private_key.bin', 'wb') as f:
        f.write(secret_key)
    with open(output_dir / 'kyber_public_key.bin', 'wb') as f:
        f.write(public_key)
    
    # Save Dilithium keys for signing
    with open(output_dir / 'dilithium_private_key.bin', 'wb') as f:
        f.write(signing_private_key)
    with open(output_dir / 'dilithium_public_key.bin', 'wb') as f:
        f.write(signing_public_key)
    
    click.echo("✅ Keys generated successfully:")
    click.echo(f"   📄 Kyber private key saved to: {output_dir}/kyber_private_key.bin")
    click.echo(f"   📄 Kyber public key saved to: {output_dir}/kyber_public_key.bin")
    click.echo(f"   📄 Dilithium private key saved to: {output_dir}/dilithium_private_key.bin")
    click.echo(f"   📄 Dilithium public key saved to: {output_dir}/dilithium_public_key.bin")

@cli.command()
@click.argument('message')
@click.option('--public-key', '-k', required=True, type=click.Path(exists=True),
              help='File containing recipient\'s public key')
@click.option('--signing-key', '-s', required=True, type=click.Path(exists=True),
              help='File containing your signing private key')
@click.option('--output', '-o', default='message.enc',
              help='Output file for the encrypted message')
def encrypt(message, public_key, signing_key, output):
    """Encrypt a message using recipient's public key."""
    # Create a new CryptoManager instance for the sender
    crypto_manager = CryptoManager()
    
    # Read keys
    with open(public_key, 'rb') as f:
        recipient_public_key = f.read()
    
    # Load sender's signing keys
    with open(signing_key, 'rb') as f:
        crypto_manager.signing_private_key = f.read()
    # Load the corresponding public key
    with open(Path(signing_key).parent / 'dilithium_public_key.bin', 'rb') as f:
        crypto_manager.signing_public_key = f.read()

    # Encrypt the message
    encrypted_data = crypto_manager.encrypt_data(
        message.encode('utf-8'),
        recipient_public_key
    )

    # Save encrypted message
    with open(output, 'wb') as f:
        f.write(encrypted_data)
    
    click.echo(f"✅ Encrypted message saved to: {output}")

@cli.command()
@click.argument('encrypted_file', type=click.Path(exists=True))
@click.option('--private-key', '-k', required=True, type=click.Path(exists=True),
              help='File containing your private key')
@click.option('--sender-signing-key', '-s', required=True, type=click.Path(exists=True),
              help='File containing sender\'s signing public key')
def decrypt(encrypted_file, private_key, sender_signing_key):
    """Decrypt a message using your private key."""
    # Create a new CryptoManager instance for the recipient
    crypto_manager = CryptoManager()
    
    # Read recipient's private key
    with open(private_key, 'rb') as f:
        recipient_private_key = f.read()
    
    # Read sender's signing public key
    with open(sender_signing_key, 'rb') as f:
        sender_public_key = f.read()
    
    # Read encrypted message
    with open(encrypted_file, 'rb') as f:
        encrypted_data = f.read()

    try:
        # Decrypt the message
        decrypted_data = crypto_manager.decrypt_data(
            encrypted_data,
            recipient_private_key,
            sender_public_key
        )

        click.echo("✅ Decrypted message:")
        click.echo(f"   📝 {decrypted_data.decode('utf-8')}")
    except ValueError as e:
        click.echo(f"❌ Error decrypting: {str(e)}")

@cli.command()
@click.argument('message')
@click.option('--signing-key', '-s', required=True, type=click.Path(exists=True),
              help='File containing your signing private key')
@click.option('--output', '-o', default='signature.bin',
              help='Output file for the signature')
def sign(message, signing_key, output):
    """Sign a message using your private key."""
    # Create a new CryptoManager instance
    crypto_manager = CryptoManager()
    
    # Load signing private key
    with open(signing_key, 'rb') as f:
        crypto_manager.signing_private_key = f.read()
    
    try:
        # Sign the message
        signature = crypto_manager.sign_data(message.encode('utf-8'))

        # Save signature
        with open(output, 'wb') as f:
            f.write(signature)
        
        click.echo(f"✅ Signature saved to: {output}")
    except ValueError as e:
        click.echo(f"❌ Error signing: {str(e)}")

@cli.command()
@click.argument('message')
@click.argument('signature', type=click.Path(exists=True))
@click.option('--public-key', '-k', required=True, type=click.Path(exists=True),
              help='File containing signer\'s public key')
def verify(message, signature, public_key):
    """Verify the signature of a message."""
    # Create a new CryptoManager instance
    crypto_manager = CryptoManager()
    
    # Read signature and public key
    with open(signature, 'rb') as f:
        signature_data = f.read()
    with open(public_key, 'rb') as f:
        public_key_data = f.read()

    # Verify the signature
    is_valid = crypto_manager.verify_signature(
        message.encode('utf-8'),
        signature_data,
        public_key_data
    )

    if is_valid:
        click.echo("✅ Valid signature: The message is authentic")
    else:
        click.echo("❌ Invalid signature: The message may have been tampered with")

@cli.command()
@click.argument('output_file', type=click.Path())
@click.option('--key-dir', '-k', required=True, type=click.Path(exists=True),
              help='Directory containing your keys')
def export_keys(output_file, key_dir):
    """Export your public keys to a file for sharing."""
    key_dir = Path(key_dir)
    
    # Read public keys
    with open(key_dir / 'kyber_public_key.bin', 'rb') as f:
        public_key = f.read()
    with open(key_dir / 'dilithium_public_key.bin', 'rb') as f:
        signing_public_key = f.read()
    
    # Create a dictionary with both public keys
    keys = {
        'public_key': base64.b64encode(public_key).decode('utf-8'),
        'signing_public_key': base64.b64encode(signing_public_key).decode('utf-8'),
        'created_at': str(datetime.datetime.now()),
        'owner': Path(key_dir).name.replace('_keys', '')
    }
    
    # Save as JSON
    with open(output_file, 'w') as f:
        json.dump(keys, f, indent=2)
    
    click.echo(f"✅ Public keys exported to: {output_file}")
    click.echo(f"   👤 Owner: {keys['owner']}")
    click.echo(f"   🕒 Created at: {keys['created_at']}")
    click.echo("\n📋 Base64 Public Keys (copy and paste friendly):")
    click.echo(f"   🔑 Kyber Public Key:\n{keys['public_key']}")
    click.echo(f"   ✍️  Dilithium Public Key:\n{keys['signing_public_key']}")

@cli.command()
@click.argument('input_file', type=click.Path(exists=True))
@click.option('--output-dir', '-o', required=True,
              help='Directory to store the imported keys')
def import_keys(input_file, output_dir):
    """Import public keys from another user."""
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    
    # Read the JSON file
    with open(input_file) as f:
        keys = json.load(f)
    
    # Extract and decode keys
    public_key = base64.b64decode(keys['public_key'])
    signing_public_key = base64.b64decode(keys['signing_public_key'])
    
    # Save the keys
    with open(output_dir / 'public_key.bin', 'wb') as f:
        f.write(public_key)
    with open(output_dir / 'signing_public_key.bin', 'wb') as f:
        f.write(signing_public_key)
    
    click.echo(f"✅ Public keys imported to: {output_dir}")
    click.echo(f"   👤 Owner: {keys['owner']}")
    click.echo(f"   🕒 Created at: {keys['created_at']}")


if __name__ == '__main__':
    cli()
