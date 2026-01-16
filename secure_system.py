"""
Secure Audio Data Exchange System

Integrates all cryptographic components:
- Camellia-128 cipher (OFB mode) for symmetric encryption
- ECDH for key exchange
- Schnorr signatures for authenticity

This is the main high-level API for secure audio exchange.
"""

import hashlib
from pathlib import Path

from crypto import Camellia, ECC, ECPoint, Schnorr
from audio import AudioHandler


class SecureSystem:
    """
    Secure Audio Data Exchange System.
    
    Provides a complete workflow for:
    1. ECDH key exchange between two parties
    2. Derivation of Camellia session key from shared secret
    3. Encryption/decryption of audio files using OFB mode
    4. Schnorr signatures for file integrity
    
    Usage (Sender - Alice):
        system = SecureSystem()
        
        # Generate keys
        alice_ecdh_priv, alice_ecdh_pub = system.generate_ecdh_keypair()
        alice_sign_priv, alice_sign_pub = system.generate_signing_keypair()
        
        # Receive Bob's ECDH public key, then:
        package = system.encrypt_and_sign(
            audio_path='song.wav',
            my_ecdh_private=alice_ecdh_priv,
            their_ecdh_public=bob_ecdh_pub,
            my_signing_private=alice_sign_priv
        )
        # Send package to Bob
    
    Usage (Receiver - Bob):
        system = SecureSystem()
        
        # Has own keys
        bob_ecdh_priv, bob_ecdh_pub = system.generate_ecdh_keypair()
        
        # Receive package from Alice, then:
        audio_data = system.verify_and_decrypt(
            package=package,
            my_ecdh_private=bob_ecdh_priv,
            their_signing_public=alice_sign_pub
        )
    """
    
    def __init__(self):
        """Initialize the secure system with all crypto components."""
        self.ecc = ECC()
        self.schnorr = Schnorr()
        self.audio_handler = AudioHandler()
    
    # =========================================================================
    # KEY GENERATION
    # =========================================================================
    
    def generate_ecdh_keypair(self) -> tuple:
        """
        Generate an ECDH key pair for key exchange.
        
        Returns:
            (private_key: int, public_key: ECPoint)
        """
        return self.ecc.generate_keypair()
    
    def generate_signing_keypair(self) -> tuple:
        """
        Generate a Schnorr key pair for signing.
        
        Returns:
            (private_key: int, public_key: ECPoint)
        """
        return self.schnorr.generate_keypair()
    
    def derive_session_key(self, my_private: int, their_public: ECPoint) -> bytes:
        """
        Derive Camellia session key from ECDH shared secret.
        
        Args:
            my_private: My ECDH private key
            their_public: Other party's ECDH public key
            
        Returns:
            16-byte Camellia key
        """
        shared_secret = self.ecc.compute_shared_secret(my_private, their_public)
        # Take first 16 bytes for 128-bit Camellia key
        return shared_secret[:16]
    
    # =========================================================================
    # ENCRYPTION WORKFLOW
    # =========================================================================
    
    def encrypt_and_sign(
        self,
        audio_path: str,
        my_ecdh_private: int,
        their_ecdh_public: ECPoint,
        my_signing_private: int
    ) -> dict:
        """
        Sign and encrypt an audio file (Case 2: Sign-then-Encrypt).
        
        Workflow (Case 2):
        1. Read audio file (plaintext P)
        2. Sign the plaintext: S = Sign(H(P)) with sender's private key
        3. Derive Camellia key from ECDH
        4. Generate random IV
        5. Encrypt with Camellia-OFB: C = E(P)
        6. Package (S, C) for transmission
        
        Args:
            audio_path: Path to audio file
            my_ecdh_private: Sender's ECDH private key
            their_ecdh_public: Receiver's ECDH public key
            my_signing_private: Sender's signing private key
            
        Returns:
            Package dict containing all data for transmission
        """
        # Step 1: Read audio file (plaintext P)
        audio_data = self.audio_handler.read(audio_path)
        file_info = self.audio_handler.get_file_info(audio_path)
        
        # Step 2: Sign the PLAINTEXT (Case 2: Sign-then-Encrypt)
        # S = E_{k2a}(H(P)) - Sign hash of plaintext with sender's private key
        plaintext_hash = hashlib.sha256(audio_data).digest()
        signature = self.schnorr.sign(plaintext_hash, my_signing_private)
        
        # Step 3: Derive session key from ECDH
        session_key = self.derive_session_key(my_ecdh_private, their_ecdh_public)
        
        # Step 4-5: Initialize Camellia and encrypt
        # C = E_{k1b}(P) - Encrypt plaintext with receiver's public key (via ECDH)
        camellia = Camellia(session_key)
        iv = Camellia.generate_iv()
        ciphertext, _ = camellia.encrypt_ofb(audio_data, iv)
        
        # Get sender's ECDH public key for package
        my_ecdh_public = self.ecc.scalar_multiply(my_ecdh_private, self.ecc.G)
        
        # Get sender's signing public key
        my_signing_public = self.schnorr.ecc.scalar_multiply(
            my_signing_private, self.schnorr.ecc.G
        )
        
        # Step 6: Package (S, C) for transmission
        package = {
            'version': 2,  # Version 2 = Sign-then-Encrypt (Case 2)
            'ecdh_public': my_ecdh_public,  # Sender's ECDH public for receiver to compute shared secret
            'signing_public': my_signing_public,  # Sender's signing public for verification
            'iv': iv,
            'ciphertext': ciphertext,
            'signature': signature,  # Signature on plaintext hash
            'original_filename': file_info['filename'],
            'original_size': file_info['size_bytes']
        }
        
        return package
    
    def verify_and_decrypt(
        self,
        package: dict,
        my_ecdh_private: int,
        their_signing_public: ECPoint = None
    ) -> bytes:
        """
        Decrypt and verify audio data (Case 2: Decrypt-then-Verify).
        
        Workflow (Case 2):
        1. Extract sender's ECDH public from package
        2. Derive Camellia key from ECDH
        3. Decrypt with Camellia-OFB: Pb = D(C)
        4. Verify signature on decrypted plaintext: D_{k1a}(S) == H(Pb)?
        
        Args:
            package: Package dict from encrypt_and_sign()
            my_ecdh_private: Receiver's ECDH private key
            their_signing_public: Sender's signing public key (optional, can use from package)
            
        Returns:
            Decrypted audio data as bytes
            
        Raises:
            ValueError: If signature verification fails
        """
        # Extract components
        sender_ecdh_public = package['ecdh_public']
        iv = package['iv']
        ciphertext = package['ciphertext']
        signature = package['signature']
        
        # Use provided signing public key or from package
        signing_public = their_signing_public or package.get('signing_public')
        if signing_public is None:
            raise ValueError("Signing public key required for verification")
        
        # Step 1: Derive session key from ECDH
        session_key = self.derive_session_key(my_ecdh_private, sender_ecdh_public)
        
        # Step 2: Decrypt first (Case 2: Decrypt-then-Verify)
        # Pb = D_{k2b}(C) - Decrypt ciphertext with receiver's private key
        camellia = Camellia(session_key)
        plaintext = camellia.decrypt_ofb(ciphertext, iv)
        
        # Step 3: Verify signature on DECRYPTED PLAINTEXT
        # D_{k1a}(S) == H(P)? - Verify that H(Pb) matches the signed hash
        plaintext_hash = hashlib.sha256(plaintext).digest()
        if not self.schnorr.verify(plaintext_hash, signature, signing_public):
            raise ValueError("Signature verification failed! Data may be tampered.")
        
        return plaintext
    
    # =========================================================================
    # FILE OPERATIONS
    # =========================================================================
    
    def encrypt_file(
        self,
        input_path: str,
        output_path: str,
        my_ecdh_private: int,
        their_ecdh_public: ECPoint,
        my_signing_private: int
    ) -> dict:
        """
        Encrypt an audio file and write to disk.
        
        Saves:
        - Ciphertext to output_path
        - Metadata (IV, signature, public keys) to output_path.meta
        
        Args:
            input_path: Source audio file
            output_path: Destination for encrypted file
            my_ecdh_private: Sender's ECDH private key
            their_ecdh_public: Receiver's ECDH public key
            my_signing_private: Sender's signing private key
            
        Returns:
            Package metadata dict
        """
        package = self.encrypt_and_sign(
            input_path,
            my_ecdh_private,
            their_ecdh_public,
            my_signing_private
        )
        
        # Write ciphertext as playable WAV file
        # This allows the encrypted file to be opened in audio players (sounds like noise)
        self.audio_handler.write_as_wav(output_path, package['ciphertext'])
        
        # Write metadata (IV, signature, public keys)
        meta_path = output_path + '.meta'
        self._write_metadata(meta_path, package)
        
        return package
    
    def decrypt_file(
        self,
        input_path: str,
        output_path: str,
        my_ecdh_private: int,
        their_signing_public: ECPoint
    ) -> int:
        """
        Decrypt an encrypted audio file.
        
        Expects:
        - Ciphertext at input_path
        - Metadata at input_path.meta
        
        Args:
            input_path: Encrypted file path
            output_path: Destination for decrypted file
            my_ecdh_private: Receiver's ECDH private key
            their_signing_public: Sender's signing public key
            
        Returns:
            Number of bytes written
        """
        # Read ciphertext - skip WAV header (44 bytes) if present
        raw_data = self.audio_handler.read(input_path)
        # Check if file has WAV header and skip it
        if raw_data[:4] == b'RIFF' and raw_data[8:12] == b'WAVE':
            # Skip 44-byte WAV header, then read original size from first 4 bytes
            data_section = raw_data[44:]
            original_size = int.from_bytes(data_section[:4], 'little')
            ciphertext = data_section[4:4 + original_size]  # Extract exact ciphertext
        else:
            ciphertext = raw_data  # Legacy .bin files without header
        
        # Read metadata
        meta_path = input_path + '.meta'
        metadata = self._read_metadata(meta_path)
        
        # Reconstruct package
        package = {
            'ecdh_public': metadata['ecdh_public'],
            'iv': metadata['iv'],
            'ciphertext': ciphertext,
            'signature': metadata['signature']
        }
        
        # Verify and decrypt
        plaintext = self.verify_and_decrypt(
            package,
            my_ecdh_private,
            their_signing_public
        )
        
        # Write decrypted audio
        return self.audio_handler.write(output_path, plaintext)
    
    # =========================================================================
    # METADATA SERIALIZATION
    # =========================================================================
    
    def _write_metadata(self, path: str, package: dict) -> None:
        """Write package metadata to file."""
        # Simple binary format:
        # - IV: 16 bytes
        # - ECDH public: 65 bytes (uncompressed)
        # - Signing public: 65 bytes (uncompressed)
        # - Signature R: 64 bytes (x,y)
        # - Signature s: 32 bytes
        # - Original size: 8 bytes
        # - Filename length: 2 bytes
        # - Filename: variable
        
        R, s = package['signature']
        
        data = bytearray()
        data.extend(package['iv'])  # 16 bytes
        data.extend(package['ecdh_public'].to_bytes())  # 65 bytes
        data.extend(package['signing_public'].to_bytes())  # 65 bytes
        data.extend(R.x.to_bytes(32, 'big'))  # 32 bytes
        data.extend(R.y.to_bytes(32, 'big'))  # 32 bytes
        data.extend(s.to_bytes(32, 'big'))  # 32 bytes
        data.extend(package['original_size'].to_bytes(8, 'big'))  # 8 bytes
        
        filename = package['original_filename'].encode('utf-8')
        data.extend(len(filename).to_bytes(2, 'big'))
        data.extend(filename)
        
        with open(path, 'wb') as f:
            f.write(data)
    
    def _read_metadata(self, path: str) -> dict:
        """Read package metadata from file."""
        with open(path, 'rb') as f:
            data = f.read()
        
        iv = data[:16]
        ecdh_public = ECPoint.from_bytes(data[16:81], self.ecc.curve)
        signing_public = ECPoint.from_bytes(data[81:146], self.ecc.curve)
        
        R_x = int.from_bytes(data[146:178], 'big')
        R_y = int.from_bytes(data[178:210], 'big')
        s = int.from_bytes(data[210:242], 'big')
        R = ECPoint(R_x, R_y, self.ecc.curve)
        signature = (R, s)
        
        original_size = int.from_bytes(data[242:250], 'big')
        filename_len = int.from_bytes(data[250:252], 'big')
        original_filename = data[252:252+filename_len].decode('utf-8')
        
        return {
            'iv': iv,
            'ecdh_public': ecdh_public,
            'signing_public': signing_public,
            'signature': signature,
            'original_size': original_size,
            'original_filename': original_filename
        }
    
    # =========================================================================
    # KEY SERIALIZATION
    # =========================================================================
    
    def export_public_keys(self, ecdh_public: ECPoint, signing_public: ECPoint) -> bytes:
        """Export public keys as bytes for sharing."""
        return ecdh_public.to_bytes() + signing_public.to_bytes()
    
    def import_public_keys(self, data: bytes) -> tuple:
        """Import public keys from bytes."""
        ecdh_public = ECPoint.from_bytes(data[:65], self.ecc.curve)
        signing_public = ECPoint.from_bytes(data[65:130], self.ecc.curve)
        return ecdh_public, signing_public


def main():
    """Demo: Alice sends encrypted audio to Bob."""
    print("=" * 60)
    print("Secure Audio Data Exchange System Demo")
    print("=" * 60)
    
    system = SecureSystem()
    
    # ==== KEY GENERATION ====
    print("\n[1] Generating keys...")
    
    # Alice's keys
    alice_ecdh_priv, alice_ecdh_pub = system.generate_ecdh_keypair()
    alice_sign_priv, alice_sign_pub = system.generate_signing_keypair()
    print("  Alice: ECDH and Schnorr key pairs generated")
    
    # Bob's keys
    bob_ecdh_priv, bob_ecdh_pub = system.generate_ecdh_keypair()
    bob_sign_priv, bob_sign_pub = system.generate_signing_keypair()
    print("  Bob: ECDH and Schnorr key pairs generated")
    
    # ==== SIMULATE AUDIO DATA ====
    print("\n[2] Creating test audio data...")
    test_audio = b"RIFF" + b"\x00" * 4 + b"WAVE" + bytes(range(256)) * 100
    print(f"  Test audio size: {len(test_audio)} bytes")
    
    # ==== ALICE SIGNS THEN ENCRYPTS (Case 2) ====
    print("\n[3] Alice signs and encrypts audio for Bob (Case 2: Sign-then-Encrypt)...")
    
    # Step 1: Sign the PLAINTEXT first
    plaintext_hash = hashlib.sha256(test_audio).digest()
    signature = system.schnorr.sign(plaintext_hash, alice_sign_priv)
    print("  Signature generated on plaintext hash")
    
    # Step 2: Derive shared key
    session_key = system.derive_session_key(alice_ecdh_priv, bob_ecdh_pub)
    print(f"  Session key derived (first 4 bytes): {session_key[:4].hex()}")
    
    # Step 3: Encrypt
    camellia = Camellia(session_key)
    iv = Camellia.generate_iv()
    ciphertext, _ = camellia.encrypt_ofb(test_audio, iv)
    print(f"  Ciphertext size: {len(ciphertext)} bytes")
    
    # ==== BOB DECRYPTS THEN VERIFIES (Case 2) ====
    print("\n[4] Bob decrypts and verifies (Case 2: Decrypt-then-Verify)...")
    
    # Step 1: Derive same shared key (from Bob's perspective)
    bob_session_key = system.derive_session_key(bob_ecdh_priv, alice_ecdh_pub)
    print(f"  Bob's session key matches: {bob_session_key == session_key}")
    
    # Step 2: Decrypt first
    bob_camellia = Camellia(bob_session_key)
    decrypted = bob_camellia.decrypt_ofb(ciphertext, iv)
    print(f"  Decrypted size: {len(decrypted)} bytes")
    
    # Step 3: Verify signature on decrypted plaintext
    decrypted_hash = hashlib.sha256(decrypted).digest()
    is_valid = system.schnorr.verify(decrypted_hash, signature, alice_sign_pub)
    print(f"  Signature valid: {is_valid}")
    
    if is_valid:
        
        # Verify content matches
        match = decrypted == test_audio
        print(f"  Content integrity verified: {match}")
    
    print("\n" + "=" * 60)
    print("Demo completed successfully!")
    print("=" * 60)


if __name__ == "__main__":
    main()
