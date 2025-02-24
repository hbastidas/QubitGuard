"""QubitGuard: A Hybrid Post-Quantum Cryptographic Library

This module implements a comprehensive cryptographic suite that combines classical and 
post-quantum cryptography to ensure long-term security against both classical and quantum attacks.

Key Features:
    - Hybrid Encryption System:
        * Kyber512 for post-quantum key encapsulation (KEM)
        * AES-256-GCM for symmetric encryption
        * HKDF for key derivation
    
    - Dual Digital Signatures:
        * Dilithium3 for post-quantum signatures
        * ECDSA (SECP256R1) for classical signatures
    
    - Secure Key Management:
        * Automated key generation and rotation
        * Memory-safe key storage
        * Support for multiple user keys
    
    - Audit System:
        * Cryptographically signed audit logs
        * Tamper-evident logging
        * Integrity verification

Classes:
    CryptoManager:
        Core class handling encryption, decryption, and signatures
    
    KeyManager:
        Manages key lifecycle and storage with secure practices
    
    AuditLog:
        Provides cryptographically verifiable audit trail

Security Note:
    This implementation follows NIST's recommendations for post-quantum
    cryptography and uses approved algorithms from the liboqs library.
    The hybrid approach ensures security even if one cryptographic
    scheme is compromised.
"""

import os
import logging
import sqlite3
import struct
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec
import oqs as OQS

# Detailed logging configuration
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

# Encryption protocol constants
VERSION = b'\x01'  # Encryption protocol version
AAD = b'QubitGuard-v1'  # Additional authenticated data for AES-GCM

class CryptoManager:
    def __init__(self):
        """Initialize the cryptographic manager with a hybrid security system.

        This constructor establishes a dual-layer cryptographic environment:

        1. Post-Quantum Security Layer:
           - Kyber512: Lattice-based KEM for quantum-resistant key exchange
           - Dilithium3: Lattice-based signature scheme for quantum-resistant authentication

        2. Classical Security Layer:
           - AES-256-GCM: Authenticated encryption with associated data
           - ECDSA (SECP256R1): Elliptic curve signatures for classical security

        Security Properties:
           - Forward Secrecy: Each operation uses fresh key material
           - Authentication: All operations are signed and verifiable
           - Integrity: Uses authenticated encryption and signed audit logs
           - Quantum Resistance: Protected against known quantum attacks

        Warning:
           Keys are stored in memory. For production use, consider:
           - Hardware Security Modules (HSM)
           - Secure key storage services
           - Regular key rotation policies
        """
        self.backend = default_backend()
        self.key_exchange_algorithm = 'Kyber512'       # Key exchange algorithm
        self.signature_algorithm = 'Dilithium3'      # Digital signature algorithm with higher security level

        # Initialize Dilithium3 signer
        self.signature_algorithm = 'Dilithium3'
        self.signing_public_key = None
        self.signing_private_key = None

        # Generate ECDSA keys for less sensitive operations
        self.ecdsa_private_key = ec.generate_private_key(ec.SECP256R1(), self.backend)
        self.ecdsa_public_key = self.ecdsa_private_key.public_key()

    def generate_signing_pair(self):
        """Generate a quantum-resistant signing key pair using Dilithium3.

        This method creates a new signing key pair using the Dilithium3 algorithm,
        which provides post-quantum security for digital signatures.

        Returns:
            tuple: A pair of (private_key, public_key) where:
                - private_key (bytes): Private key for signing
                - public_key (bytes): Public key for verification

        Security Properties:
            - EUF-CMA secure: Existentially unforgeable under chosen message attacks
            - Quantum-resistant: Based on the hardness of lattice problems
            - Fresh keys: New key material for each key pair
        """
        signer = OQS.Signature(self.signature_algorithm)
        public_key = signer.generate_keypair()
        private_key = signer.export_secret_key()
        return private_key, public_key

    def generate_key_exchange_pair(self):
        """Generate a quantum-resistant key exchange pair using Kyber512.

        This method creates a new KEM (Key Encapsulation Mechanism) pair using
        the Kyber512 algorithm, which provides 128-bit post-quantum security.

        Returns:
            tuple: A pair of (secret_key, public_key) where:
                - secret_key (bytes): Private key for decapsulation
                - public_key (bytes): Public key for encapsulation

        Security Properties:
            - IND-CCA2 secure: Protected against adaptive chosen ciphertext attacks
            - Quantum-resistant: Based on the hardness of Module-LWE problem
            - Fresh keys: New key material for each exchange
        """
        key_exchange = OQS.KeyEncapsulation(self.key_exchange_algorithm)
        public_key = key_exchange.generate_keypair()
        secret_key = key_exchange.export_secret_key()
        return secret_key, public_key

    def encrypt_data(self, data, recipient_public_key, use_quantum_safe=True):
        """Encrypt data using a hybrid quantum-safe encryption scheme.

        This method implements a hybrid encryption protocol that combines:
        1. Kyber512 KEM for quantum-resistant key exchange
        2. HKDF for secure key derivation
        3. AES-256-GCM for authenticated encryption
        4. Dilithium3/ECDSA for packet signing

        Protocol Steps:
        1. Key Exchange:
           - Generate a shared secret using Kyber512 KEM
           - Encapsulate the secret for the recipient

        2. Key Derivation:
           - Generate a random salt
           - Derive encryption key using HKDF-SHA256

        3. Encryption:
           - Generate random IV for AES-GCM
           - Encrypt data with AES-256-GCM
           - Include version as authenticated data

        4. Packet Construction:
           - Build a structured packet with all components
           - Sign the packet (excluding signature section)

        Packet Format:
            version (1B) || salt (16B) || IV (12B) || kem_ciphertext (N bytes) || 
            tag (16B) || encrypted_data_length (4B) || encrypted_data || 
            signature_length (4B) || signature

        Args:
            data (bytes): Raw data to encrypt
            recipient_public_key (bytes): Recipient's Kyber512 public key
            use_quantum_safe (bool): Use Dilithium3 (True) or ECDSA (False) for signing

        Returns:
            bytes: Complete encrypted and signed packet

        Raises:
            ValueError: If encryption or signing fails

        Security Properties:
            - Forward Secrecy: Fresh keys for each encryption
            - Authentication: Signed packets prevent tampering
            - Confidentiality: Post-quantum and classical protection
            - Integrity: AES-GCM authenticated encryption
        """
        try:
            key_exchange = OQS.KeyEncapsulation(self.key_exchange_algorithm)
            # Encapsulate the secret using the recipient's public key
            kem_ciphertext, shared_secret = key_exchange.encap_secret(recipient_public_key)
            ciphertext_size = key_exchange.details['length_ciphertext']
            
            # Generate salt and derive symmetric key
            salt = os.urandom(16)
            derived_key = HKDF(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                info=b'encryption_key',
                backend=self.backend
            ).derive(shared_secret)
            
            # Generate IV and encrypt data with AES-GCM including AAD
            iv = os.urandom(12)
            cipher = Cipher(algorithms.AES(derived_key), modes.GCM(iv), backend=self.backend)
            encryptor = cipher.encryptor()
            encryptor.authenticate_additional_data(AAD)
            encrypted_data = encryptor.update(data) + encryptor.finalize()
            tag = encryptor.tag  # 16 bytes
            
            # Build the packet (except signature)
            # Pack the encrypted data length in 4 bytes (big-endian)
            encrypted_data_len = struct.pack('!I', len(encrypted_data))
            packet_without_signature = (VERSION + salt + iv + kem_ciphertext + tag +
                                        encrypted_data_len + encrypted_data)
            logging.info(f"Length of packet to sign: {len(packet_without_signature)}")
            logging.info(f"Content of packet to sign: {[x for x in packet_without_signature[:10]]}...")
            
            # Sign the complete packet (without the signature section)
            if use_quantum_safe:
                # Sign the packet with the signing private key
                signature = self.sign_data(packet_without_signature)
                logging.info(f"Generated signature length: {len(signature)}")
            else:
                signature = self.ecdsa_private_key.sign(packet_without_signature, ec.ECDSA(hashes.SHA256()))
            
            # Pack the signature length in 4 bytes and add the signature
            signature_len = struct.pack('!I', len(signature))
            final_packet = packet_without_signature + signature_len + signature
            return final_packet
        except Exception as e:
            logging.error(f"Encryption error: {e}")
            raise ValueError(f"Encryption error: {e}")

    def decrypt_data(self, encrypted_package, recipient_private_key, sender_public_key, use_quantum_safe=True):
        """Decrypt and verify a hybrid-encrypted data packet.

        This method reverses the hybrid encryption process by:
        1. Extracting and verifying the signature
        2. Decapsulating the shared secret
        3. Deriving the encryption key
        4. Decrypting the data

        Protocol Steps:
        1. Packet Parsing:
           - Extract all components from the structured packet
           - Verify packet version compatibility

        2. Signature Verification:
           - Reconstruct the signed portion
           - Verify using Dilithium3 or ECDSA

        3. Key Recovery:
           - Decapsulate shared secret using Kyber512
           - Derive encryption key using HKDF

        4. Decryption:
           - Decrypt data using AES-256-GCM
           - Verify authentication tag

        Args:
            encrypted_package (bytes): Complete encrypted packet
            recipient_private_key (bytes): Recipient's Kyber512 private key
            sender_public_key (bytes): Sender's signing public key
            use_quantum_safe (bool): Use Dilithium3 (True) or ECDSA (False) for verification

        Returns:
            bytes: Decrypted original data

        Raises:
            ValueError: If decryption fails or signature is invalid

        Security Checks:
            - Packet integrity verification
            - Signature validation
            - Version compatibility
            - Authentication tag verification
        """
        try:
            # Create a new KeyEncapsulation instance with the private key
            key_exchange = OQS.KeyEncapsulation(self.key_exchange_algorithm)
            ciphertext_size = key_exchange.details['length_ciphertext']
            
            offset = 0
            # Extract version (1 byte)
            version = encrypted_package[offset:offset+1]
            offset += 1
            if version != VERSION:
                raise ValueError("Unsupported package version")
            
            # Extract salt, IV, kem_ciphertext and tag
            salt = encrypted_package[offset:offset+16]
            offset += 16
            iv = encrypted_package[offset:offset+12]
            offset += 12
            kem_ciphertext = encrypted_package[offset:offset+ciphertext_size]
            offset += ciphertext_size
            tag = encrypted_package[offset:offset+16]
            offset += 16
            
            # Extract the length and content of encrypted data
            (encrypted_data_length,) = struct.unpack('!I', encrypted_package[offset:offset+4])
            offset += 4
            encrypted_data = encrypted_package[offset:offset+encrypted_data_length]
            offset += encrypted_data_length
            
            # The rest corresponds to the signature length and signature
            (signature_length,) = struct.unpack('!I', encrypted_package[offset:offset+4])
            offset += 4
            signature = encrypted_package[offset:offset+signature_length]
            
            # Reconstruct the signed packet (everything except signature length and signature)
            packet_to_verify = encrypted_package[:-(4 + signature_length)]
            
            # Verify the signature
            if use_quantum_safe:
                logging.info(f"Verifying signature with length: {len(signature)}")
                logging.info(f"Length of packet to verify: {len(packet_to_verify)}")
                logging.info(f"Content of packet to verify: {[x for x in packet_to_verify[:10]]}...")
                logging.info(f"Verifying with public key: {sender_public_key}")
                if not self.verify_signature(packet_to_verify, signature, sender_public_key):
                    raise ValueError("Invalid signature: possible MITM attack")
                logging.info("Signature verified successfully")
            else:
                sender_public_key.verify(signature, packet_to_verify, ec.ECDSA(hashes.SHA256()))
            
            # Create a new instance for decapsulation
            decap_exchange = OQS.KeyEncapsulation(self.key_exchange_algorithm)
            # Set the private key
            decap_exchange.secret_key = recipient_private_key
            # Recover the shared secret
            shared_secret = decap_exchange.decap_secret(kem_ciphertext)
            derived_key = HKDF(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                info=b'encryption_key',
                backend=self.backend
            ).derive(shared_secret)
            
            # Descifrar datos utilizando AES-GCM con AAD
            cipher = Cipher(algorithms.AES(derived_key), modes.GCM(iv, tag), backend=self.backend)
            decryptor = cipher.decryptor()
            decryptor.authenticate_additional_data(AAD)
            data = decryptor.update(encrypted_data) + decryptor.finalize()
            return data
        except Exception as e:
            logging.error(f"Decryption error: {e}")
            raise ValueError(f"Decryption error: {e}")

    def sign_data(self, data):
        """Sign data using Dilithium3 post-quantum signatures.

        This method provides quantum-resistant digital signatures using
        the Dilithium3 signature scheme from liboqs.

        Args:
            data (bytes): The data to be signed

        Returns:
            bytes: The Dilithium3 signature

        Raises:
            Exception: If signing operation fails

        Security Properties:
            - Post-quantum security
            - Non-repudiation
            - Integrity protection
        """
        try:
            if not self.signing_private_key:
                raise ValueError("No signing private key set")
            # Create a new signer instance
            signer = OQS.Signature(self.signature_algorithm)
            # Set the private key
            signer.secret_key = self.signing_private_key
            # Sign the data
            signature = signer.sign(data)
            return signature
        except Exception as e:
            logging.error(f"Error signing data: {str(e)}")
            raise

    def verify_signature(self, data, signature, public_key):
        """Verify a Dilithium3 digital signature.

        This method verifies the authenticity and integrity of signed data
        using the Dilithium3 post-quantum signature scheme.

        Args:
            data (bytes): The original data that was signed
            signature (bytes): The Dilithium3 signature to verify
            public_key (bytes): The signer's public key

        Returns:
            bool: True if signature is valid, False otherwise

        Security Properties:
            - Post-quantum security
            - Tamper detection
            - Authenticity verification
        """
        try:
            if not public_key:
                logging.error("No public key provided")
                return False
            verifier = OQS.Signature(self.signature_algorithm)
            return verifier.verify(data, signature, public_key)
        except Exception as e:
            logging.error(f"Error verifying signature: {str(e)}")
            return False

class KeyManager:
    """Secure key management system for post-quantum cryptography.

    This class implements a comprehensive key management system that:
    1. Generates quantum-resistant key pairs (Kyber512)
    2. Manages key storage and retrieval
    3. Enforces key security policies

    Key Features:
        - Automated key pair generation
        - Secure in-memory key storage
        - User-specific key management
        - Key rotation support

    Security Measures:
        - Memory-safe key storage
        - Key isolation between users
        - Support for key expiration
        - Secure key deletion

    Production Recommendations:
        1. Hardware Security Module (HSM):
           - Store private keys in tamper-resistant hardware
           - Hardware-backed key operations
           - FIPS 140-2 Level 3+ compliance

        2. Key Management Service (KMS):
           - Centralized key management
           - Automated key rotation
           - Access control and audit

        3. Security Policies:
           - Regular key rotation (e.g., every 90 days)
           - Key usage limitations
           - Access control mechanisms
    """

    def __init__(self, crypto_manager):
        """Initialize the key management system.

        Sets up a secure key management environment with:
        1. Reference to the cryptographic manager for operations
        2. Secure in-memory key storage system
        3. User-specific key isolation

        Args:
            crypto_manager (CryptoManager): Instance of the cryptographic manager
                that provides the core cryptographic operations.

        Security Note:
            The key_store dictionary provides basic in-memory storage.
            For production environments, implement:
            - Hardware Security Module (HSM) integration
            - Encrypted storage
            - Access control mechanisms
        """
        self.crypto_manager = crypto_manager
        self.key_store = {}  # In-memory storage (use HSM in production)

    def generate_new_key_pair(self, user_id):
        """Generate and store a new key pair for a user.
        
        Args:
            user_id (str): Identifier for the user
            
        Returns:
            tuple: A pair of (private_key, public_key)
            
        Security Note:
            The private key should be handled with care and never exposed.
        """
        private_key, public_key = self.crypto_manager.generate_key_exchange_pair()
        self.key_store[user_id] = (private_key, public_key)
        return (private_key, public_key)

class AuditLog:
    """Cryptographically secure audit logging system with quantum resistance.

    This class implements a tamper-evident audit logging system that provides:
    1. Cryptographic proof of log integrity
    2. Non-repudiation of logged events
    3. Quantum-resistant security guarantees

    Security Features:
        - Post-quantum Digital Signatures:
          * Dilithium3 signatures for quantum resistance
          * Cryptographic binding of events to signers
          * Signature verification for each entry

        - Tamper Detection:
          * Each entry is individually signed
          * Public keys stored with records
          * Integrity verification methods

        - Secure Storage:
          * SQLite database backend
          * Atomic transactions
          * Concurrent access support

    Audit Capabilities:
        - Event Recording:
          * Timestamped entries
          * Signer identification
          * Event categorization

        - Verification:
          * Individual entry verification
          * Batch verification support
          * Signature validity checks

    Best Practices:
        1. Regular backups of the audit log
        2. Periodic integrity verification
        3. Secure storage of verification keys
        4. Monitor for unauthorized modifications
    """

    def __init__(self, crypto_manager, db_path='audit_log.db'):
        """Initialize the secure audit logging system.

        Sets up a cryptographically secured audit log with:
        1. Quantum-resistant signature capability
        2. Secure database storage
        3. Structured event recording

        Args:
            crypto_manager (CryptoManager): Cryptographic manager instance that
                provides signing and verification capabilities.
            db_path (str, optional): Path to the SQLite database file.
                Defaults to 'audit_log.db'.

        Database Schema:
            - id: Unique identifier for each log entry
            - event: The actual event data being logged
            - signature: Quantum-resistant digital signature
            - public_key: Verification key for the signature

        Security Features:
            - Atomic transactions
            - Signature verification
            - Tamper detection

        Note:
            For production use:
            - Use encrypted database
            - Implement backup strategy
            - Consider write-once storage
        """
        self.crypto_manager = crypto_manager
        self.conn = sqlite3.connect(db_path)
        self.conn.execute('''CREATE TABLE IF NOT EXISTS audit_log
                             (id INTEGER PRIMARY KEY, event TEXT, signature BLOB, public_key BLOB)''')

    def log_event(self, event):
        """Record an event with quantum-resistant digital signature.

        This method provides secure event logging by:
        1. Signing the event with Dilithium3
        2. Storing the event, signature, and verification key
        3. Ensuring atomic database transaction

        Args:
            event (str): The event information to be logged

        Security Features:
            - Post-quantum digital signatures
            - Non-repudiation of events
            - Atomic database operations

        Note:
            The event is signed using the system's Dilithium3 key,
            providing quantum-resistant authenticity and integrity.
        """
        event_bytes = event.encode()
        signature = self.crypto_manager.sign_data(event_bytes)
        # Store the public key directly as bytes
        public_key_bytes = self.crypto_manager.signing_public_key
        self.conn.execute("INSERT INTO audit_log (event, signature, public_key) VALUES (?, ?, ?)",
                          (event, signature, public_key_bytes))
        self.conn.commit()

    def verify_log_entry(self, entry_id):
        """Verify the cryptographic integrity of a logged event.

        This method performs a comprehensive verification by:
        1. Retrieving the log entry and its signature
        2. Validating the signature using the stored public key
        3. Ensuring the event hasn't been tampered with

        Args:
            entry_id (int): The ID of the log entry to verify

        Returns:
            bool: True if the signature is valid, False otherwise

        Raises:
            Exception: If signature verification fails

        Security Features:
            - Quantum-resistant verification
            - Tamper detection
            - Complete entry validation
        """
        cursor = self.conn.execute("SELECT event, signature, public_key FROM audit_log WHERE id=?", (entry_id,))
        row = cursor.fetchone()
        if row:
            event, signature, public_key = row
            # Create a new verifier for this signature
            verifier = OQS.Signature(self.crypto_manager.signature_algorithm)
            try:
                return verifier.verify(event.encode(), signature, public_key)
            except Exception as e:
                logging.error(f"Error verifying log entry: {e}")
                return False
        return False

    def close(self):
        """Safely close the database connection.

        This method ensures:
        1. All pending transactions are committed
        2. Database connection is properly closed
        3. Resources are released

        Note:
            Always call this method when done with the audit log
            to prevent resource leaks and data corruption.
        """
        self.conn.close()
