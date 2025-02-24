# QubitGuard - Post-Quantum Cryptographic Tools

QubitGuard is a Python package that provides post-quantum cryptographic tools for secure communication. It implements Kyber for key exchange and encryption, and Dilithium for digital signatures, making it resistant to potential quantum computer attacks.

## Features

- **Post-Quantum Key Exchange**: Using Kyber algorithm
- **Post-Quantum Digital Signatures**: Using Dilithium algorithm
- **Secure Message Exchange**: End-to-end encrypted communication
- **Key Management**: Export and import of public keys
- **Command-Line Interface**: Easy-to-use CLI for all operations

## Installation

```bash
pip install qubitguard
```

## Quick Start

### 1. Generate Keys

First, both parties need to generate their key pairs:

```bash
# Alice generates her keys
python -m QubitGuard.cli genkeys --output-dir alice_keys

# Bob generates his keys
python -m QubitGuard.cli genkeys --output-dir bob_keys
```

### 2. Exchange Public Keys

Export and share public keys:

```bash
# Alice exports her public keys
python -m QubitGuard.cli export-keys alice_public.json --key-dir alice_keys

# Bob exports his public keys
python -m QubitGuard.cli export-keys bob_public.json --key-dir bob_keys

# Alice imports Bob's public keys
python -m QubitGuard.cli import-keys bob_public.json --output-dir alice/bob_keys

# Bob imports Alice's public keys
python -m QubitGuard.cli import-keys alice_public.json --output-dir bob/alice_keys
```

### 3. Send Encrypted Messages

Send and receive encrypted messages:

```bash
# Alice sends a message to Bob
python -m QubitGuard.cli encrypt "Hello Bob! This is a secret message." \
    --public-key bob_keys/public_key.bin \
    --signing-key alice_keys/signing_private_key.bin \
    --output message_to_bob.enc

# Bob decrypts Alice's message
python -m QubitGuard.cli decrypt message_to_bob.enc \
    --private-key bob_keys/private_key.bin \
    --sender-signing-key alice_keys/signing_public_key.bin
```

## CLI Commands

### `genkeys`
Generate a new key pair for encryption and signing.
```bash
python -m QubitGuard.cli genkeys --output-dir <directory>
```

### `export-keys`
Export public keys to share with others.
```bash
python -m QubitGuard.cli export-keys <output_file> --key-dir <directory>
```

### `import-keys`
Import someone else's public keys.
```bash
python -m QubitGuard.cli import-keys <input_file> --output-dir <directory>
```

### `encrypt`
Encrypt a message using recipient's public key.
```bash
python -m QubitGuard.cli encrypt <message> --public-key <key_file> --signing-key <key_file> --output <file>
```

### `decrypt`
Decrypt a message using your private key.
```bash
python -m QubitGuard.cli decrypt <encrypted_file> --private-key <key_file> --sender-signing-key <key_file>
```

### `sign`
Sign a message using your private signing key.
```bash
python -m QubitGuard.cli sign <message> --signing-key <key_file> --output <file>
```

### `verify`
Verify a message's signature using the sender's public key.
```bash
python -m QubitGuard.cli verify <message> <signature> --public-key <key_file>
```

## Complete Demonstration: Alice and Bob's Secure Communication

Here's a complete example showing how Alice and Bob can set up secure communication:

### 1. Initial Setup

```bash
# Create directories for Alice and Bob
mkdir -p alice_keys bob_keys

# Generate keys for both parties
python -m QubitGuard.cli genkeys --output-dir alice_keys
python -m QubitGuard.cli genkeys --output-dir bob_keys
```

### 2. Exchange Public Keys

```bash
# Export public keys
python -m QubitGuard.cli export-keys alice_public.json --key-dir alice_keys
python -m QubitGuard.cli export-keys bob_public.json --key-dir bob_keys

# Create directories for storing each other's keys
mkdir -p alice_keys/bob_keys bob_keys/alice_keys

# Import each other's public keys
python -m QubitGuard.cli import-keys bob_public.json --output-dir alice_keys/bob_keys
python -m QubitGuard.cli import-keys alice_public.json --output-dir bob_keys/alice_keys
```

### 3. Secure Communication

```bash
# Alice sends an encrypted message to Bob
python -m QubitGuard.cli encrypt "Hello Bob! This is a secret message from Alice." \
    --public-key alice_keys/bob_keys/public_key.bin \
    --signing-key alice_keys/dilithium_private_key.bin \
    --output alice_to_bob.enc

# Bob decrypts and verifies Alice's message
python -m QubitGuard.cli decrypt alice_to_bob.enc \
    --private-key bob_keys/kyber_private_key.bin \
    --sender-signing-key bob_keys/alice_keys/signing_public_key.bin

# Bob replies to Alice
python -m QubitGuard.cli encrypt "Hi Alice! I received your message. The secure communication works!" \
    --public-key bob_keys/alice_keys/public_key.bin \
    --signing-key bob_keys/dilithium_private_key.bin \
    --output bob_to_alice.enc

# Alice decrypts and verifies Bob's reply
python -m QubitGuard.cli decrypt bob_to_alice.enc \
    --private-key alice_keys/kyber_private_key.bin \
    --sender-signing-key alice_keys/bob_keys/signing_public_key.bin
```

### 4. Additional Security Operations

```bash
# Alice signs a message
python -m QubitGuard.cli sign "This message is authentically from Alice" \
    --signing-key alice_keys/dilithium_private_key.bin \
    --output alice_signature.bin

# Bob verifies Alice's signature
python -m QubitGuard.cli verify "This message is authentically from Alice" \
    alice_signature.bin \
    --public-key bob_keys/alice_keys/signing_public_key.bin
```

This demonstration shows:
- Key generation and management
- Public key exchange
- Encrypted message exchange
- Message signing and verification
- Use of separate keys for encryption and signing
- Full end-to-end secure communication workflow

## Security Features

- **Post-Quantum Security**: Resistant to attacks from both classical and quantum computers
- **Perfect Forward Secrecy**: Each message uses unique encryption keys
- **Message Authentication**: All messages are signed and verified
- **Key Separation**: Different keys for encryption and signing

## Roadmap - Future Improvements

### 1. Documentation
- Add Google/NumPy style docstrings to all functions
- Create detailed Sphinx documentation
- Add more advanced usage examples
- Improve API documentation

### 2. Distribution
- Publish package to PyPI
- Add CONTRIBUTING.md file for future contributors
- Create CHANGELOG.md to track version changes
- Improve installation and setup process

### 3. Additional Features
- Support for multiple post-quantum algorithms
- Fallback functions to classical algorithms
- More robust key management system with automatic rotation
- Support for user groups (not just one-to-one communication)
- Implement public key caching

### 4. Security
- Add more security tests
- Implement stricter input validation
- Add security auditing
- Add key integrity checks
- Improve logging and audit system

### 5. CI/CD
- Configure GitHub Actions for:
  - Automated test execution
  - Code coverage verification
  - Static code analysis
  - Automated deployment

### 6. CLI Improvements
- Add more useful commands
- Improve error handling and user messages
- Add interactive interface
- Add support for configuration via file

### 7. Performance
- Optimize cryptographic operations
- Add support for asynchronous operations
- Improve memory handling for large data volumes
- Implement parallel processing for intensive operations

## Development

### Running Tests

```bash
python -m pytest tests/
```

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.ion
- **Digital Signatures**: Implementation of post-quantum digital signatures
- **Audit Logging**: Logging system to track all cryptographic operations

## Installation

### Prerequisites

- Python 3.8 or higher
- pip (Python package manager)

### Basic Installation

```bash
pip install .
```

### Installation with Post-Quantum Support

```bash
pip install .[quantum]
```

## Basic Usage

```python
from QubitGuard.crypto_manager import CryptoManager, KeyManager, AuditLog

# Initialize components
crypto_manager = CryptoManager()
key_manager = KeyManager(crypto_manager)
audit_log = AuditLog(crypto_manager)

# Generate key pair for a user
user_id = "user123"
key_manager.generate_new_key_pair(user_id)
private_key, public_key = key_manager.key_store[user_id]

# Encrypt data
message = "Secret message"
encrypted_message = crypto_manager.encrypt_data(message.encode(), public_key)

# Decrypt data
decrypted_message = crypto_manager.decrypt_data(
    encrypted_message,
    private_key,
    crypto_manager.signing_public_key
)

# Log event
audit_log.log_event("Encryption operation completed")
```

## Development

### Development Environment Setup

```bash
# Create virtual environment
python -m venv env
source env/bin/activate  # On Linux/Mac
env\Scripts\activate  # On Windows

# Install in development mode
pip install -e .[quantum]

# Install development dependencies
pip install pytest
```

### Running Tests

```bash
python -m pytest test_crypto_suite.py -v
```

## Security

- Private keys should never be shared or stored in plaintext
- The audit log should be protected and backed up regularly
- Keys should be rotated periodically
- Keep the system and dependencies up to date

## License

This project is licensed under the MIT License - see the LICENSE file for details.
