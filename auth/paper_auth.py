"""
Paper-Based Authentication Module

Implements secure authentication using PBKDF2-HMAC-SHA256 with 100,000 iterations.
Credentials are stored in credentials.json with salted password hashes.

Security Features:
- PBKDF2-HMAC-SHA256 key derivation
- 100,000 iterations for computational cost
- Random salt generation per user
- Secure password verification
"""

import hashlib
import secrets
import json
import os
from pathlib import Path


class PaperAuth:
    """
    Paper-based authentication using PBKDF2.
    
    Requires both a passphrase (Paper) and a salt for authentication.
    Uses PBKDF2-HMAC-SHA256 with 100,000 iterations.
    """
    
    # Security parameters
    ITERATIONS = 100_000
    HASH_ALGORITHM = 'sha256'
    KEY_LENGTH = 32  # 256 bits
    SALT_LENGTH = 32  # 256 bits
    
    def __init__(self, credentials_path: str = None):
        """
        Initialize PaperAuth.
        
        Args:
            credentials_path: Path to credentials.json file.
                            If None, uses default path in project root.
        """
        if credentials_path is None:
            # Default to project root
            self.credentials_path = Path(__file__).parent.parent / 'credentials.json'
        else:
            self.credentials_path = Path(credentials_path)
        
        self._ensure_credentials_file()
    
    def _ensure_credentials_file(self) -> None:
        """Create credentials file if it doesn't exist."""
        if not self.credentials_path.exists():
            self._save_credentials({})
    
    def _load_credentials(self) -> dict:
        """Load credentials from JSON file."""
        try:
            with open(self.credentials_path, 'r') as f:
                return json.load(f)
        except (json.JSONDecodeError, FileNotFoundError):
            return {}
    
    def _save_credentials(self, credentials: dict) -> None:
        """Save credentials to JSON file."""
        with open(self.credentials_path, 'w') as f:
            json.dump(credentials, f, indent=2)
    
    def _derive_key(self, passphrase: str, salt: bytes) -> bytes:
        """
        Derive key from passphrase using PBKDF2-HMAC-SHA256.
        
        Args:
            passphrase: User's paper/passphrase
            salt: Random salt bytes
            
        Returns:
            Derived key bytes
        """
        return hashlib.pbkdf2_hmac(
            self.HASH_ALGORITHM,
            passphrase.encode('utf-8'),
            salt,
            self.ITERATIONS,
            dklen=self.KEY_LENGTH
        )
    
    def register_user(self, username: str, passphrase: str) -> dict:
        """
        Register a new user with their passphrase.
        
        Args:
            username: User identifier (e.g., 'alice', 'bob')
            passphrase: User's paper/passphrase
            
        Returns:
            dict with 'salt' (hex string) that user must store securely
            
        Raises:
            ValueError: If username already exists
        """
        credentials = self._load_credentials()
        
        if username.lower() in credentials:
            raise ValueError(f"User '{username}' already registered")
        
        # Generate random salt
        salt = secrets.token_bytes(self.SALT_LENGTH)
        
        # Derive key from passphrase
        derived_key = self._derive_key(passphrase, salt)
        
        # Store credentials
        credentials[username.lower()] = {
            'salt': salt.hex(),
            'key_hash': derived_key.hex()
        }
        
        self._save_credentials(credentials)
        
        return {
            'username': username.lower(),
            'salt': salt.hex()
        }
    
    def authenticate(self, username: str, passphrase: str, salt_hex: str) -> bool:
        """
        Authenticate a user with passphrase and salt.
        
        Args:
            username: User identifier
            passphrase: User's paper/passphrase
            salt_hex: Salt as hex string (from credentials.json or stored)
            
        Returns:
            True if authentication successful, False otherwise
        """
        credentials = self._load_credentials()
        
        username_lower = username.lower()
        if username_lower not in credentials:
            return False
        
        stored = credentials[username_lower]
        
        # Verify the provided salt matches stored salt
        if stored['salt'] != salt_hex:
            return False
        
        # Convert salt from hex to bytes
        try:
            salt = bytes.fromhex(salt_hex)
        except ValueError:
            return False
        
        # Derive key from provided passphrase
        derived_key = self._derive_key(passphrase, salt)
        
        # Compare with stored hash using constant-time comparison
        return secrets.compare_digest(
            derived_key.hex(),
            stored['key_hash']
        )
    
    def user_exists(self, username: str) -> bool:
        """Check if a user is registered."""
        credentials = self._load_credentials()
        return username.lower() in credentials
    
    def get_user_salt(self, username: str) -> str:
        """
        Get the salt for a registered user.
        
        Args:
            username: User identifier
            
        Returns:
            Salt as hex string
            
        Raises:
            ValueError: If user not found
        """
        credentials = self._load_credentials()
        
        username_lower = username.lower()
        if username_lower not in credentials:
            raise ValueError(f"User '{username}' not found")
        
        return credentials[username_lower]['salt']
    
    def delete_user(self, username: str) -> bool:
        """
        Delete a user's credentials.
        
        Args:
            username: User identifier
            
        Returns:
            True if user was deleted, False if not found
        """
        credentials = self._load_credentials()
        
        username_lower = username.lower()
        if username_lower not in credentials:
            return False
        
        del credentials[username_lower]
        self._save_credentials(credentials)
        return True
    
    def reset_credentials(self) -> None:
        """Reset all credentials (for testing/development)."""
        self._save_credentials({})
    
    def list_users(self) -> list:
        """List all registered usernames."""
        credentials = self._load_credentials()
        return list(credentials.keys())


# Convenience function for quick authentication
def quick_auth(username: str, passphrase: str, salt_hex: str) -> bool:
    """
    Quick authentication helper.
    
    Args:
        username: User identifier
        passphrase: User's passphrase
        salt_hex: Salt hex string
        
    Returns:
        True if authenticated, False otherwise
    """
    auth = PaperAuth()
    return auth.authenticate(username, passphrase, salt_hex)

