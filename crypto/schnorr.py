"""
Schnorr Digital Signature Scheme Implementation

Implements Schnorr signatures over elliptic curves:
- Key generation
- Signing: s = k + e*x (mod n)
- Verification: sG = R + eP

Security based on the Discrete Logarithm Problem.
NO external crypto libraries used. Only hashlib.
"""

import hashlib
from .utils import secure_random_below
from .ecc import ECC, ECPoint, NIST_P256


class Schnorr:
    """
    Schnorr Digital Signature Scheme over elliptic curves.
    
    Provides:
    - Key generation
    - Message signing
    - Signature verification
    
    Security properties:
    - Provable security under Random Oracle Model
    - Reduces to Discrete Logarithm Problem
    - Linear signatures (enables aggregation)
    
    Usage:
        schnorr = Schnorr()
        private_key, public_key = schnorr.generate_keypair()
        signature = schnorr.sign(message, private_key)
        valid = schnorr.verify(message, signature, public_key)
    """
    
    def __init__(self, curve: dict = None):
        """
        Initialize Schnorr signature scheme.
        
        Args:
            curve: Curve parameters dict (defaults to NIST P-256)
        """
        self.curve = curve if curve is not None else NIST_P256
        self.ecc = ECC(self.curve)
    
    def generate_keypair(self) -> tuple:
        """
        Generate a Schnorr key pair.
        
        Private key: Random integer x in [1, n-1]
        Public key: Point P = xG
        
        Returns:
            (private_key, public_key) tuple where:
                - private_key is an integer
                - public_key is an ECPoint
        """
        return self.ecc.generate_keypair()
    
    def _hash_challenge(self, R: ECPoint, P: ECPoint, message: bytes) -> int:
        """
        Compute the challenge hash e = H(R || P || m) mod n.
        
        This is the Fiat-Shamir heuristic that makes the signature
        non-interactive.
        
        Args:
            R: Commitment point (kG)
            P: Public key
            message: Message being signed
            
        Returns:
            Challenge integer e in [0, n-1]
        """
        # Construct hash input: R.x || R.y || P.x || P.y || message
        hash_input = (
            R.x.to_bytes(32, 'big') +
            R.y.to_bytes(32, 'big') +
            P.x.to_bytes(32, 'big') +
            P.y.to_bytes(32, 'big') +
            message
        )
        
        # SHA-256 hash
        h = hashlib.sha256(hash_input).digest()
        
        # Convert to integer mod n
        e = int.from_bytes(h, 'big') % self.curve['n']
        
        return e
    
    def sign(self, message: bytes, private_key: int) -> tuple:
        """
        Create a Schnorr signature.
        
        Algorithm:
        1. k ← random in [1, n-1]     (ephemeral nonce)
        2. R = kG                      (commitment point)
        3. e = H(R || P || m) mod n    (challenge hash)
        4. s = (k + e * x) mod n       (response)
        5. Return signature (R, s)
        
        CRITICAL: Never reuse the nonce k! If the same k is used for
        two different messages, the private key can be recovered.
        
        Args:
            message: Message bytes to sign
            private_key: Signer's private key (integer)
            
        Returns:
            (R, s) tuple where:
                - R is an ECPoint (commitment)
                - s is an integer (response)
        """
        n = self.curve['n']
        G = self.ecc.G
        
        # Compute public key for hash
        P = self.ecc.scalar_multiply(private_key, G)
        
        # Generate random nonce k in [1, n-1]
        # CRITICAL: This must be cryptographically random!
        k = secure_random_below(n - 1) + 1
        
        # Compute commitment R = kG
        R = self.ecc.scalar_multiply(k, G)
        
        # Compute challenge e = H(R || P || m) mod n
        e = self._hash_challenge(R, P, message)
        
        # Compute response s = (k + e * x) mod n
        s = (k + e * private_key) % n
        
        return (R, s)
    
    def verify(self, message: bytes, signature: tuple, public_key: ECPoint) -> bool:
        """
        Verify a Schnorr signature.
        
        Algorithm:
        1. Parse signature as (R, s)
        2. e = H(R || P || m) mod n    (recompute challenge)
        3. Compute LHS = sG
        4. Compute RHS = R + eP
        5. Verify: LHS == RHS
        
        Correctness proof:
            sG = (k + e*x)G = kG + e*xG = R + eP ✓
        
        Args:
            message: Original message bytes
            signature: (R, s) tuple from sign()
            public_key: Signer's public key (ECPoint)
            
        Returns:
            True if signature is valid, False otherwise
        """
        R, s = signature
        n = self.curve['n']
        G = self.ecc.G
        
        # Validate inputs
        if not isinstance(R, ECPoint):
            return False
        if not R.is_on_curve():
            return False
        if not public_key.is_on_curve():
            return False
        if not (0 < s < n):
            return False
        
        # Recompute challenge e = H(R || P || m) mod n
        e = self._hash_challenge(R, public_key, message)
        
        # Compute LHS = sG
        lhs = self.ecc.scalar_multiply(s, G)
        
        # Compute RHS = R + e*P
        eP = self.ecc.scalar_multiply(e, public_key)
        rhs = self.ecc.point_add(R, eP)
        
        # Verify: sG == R + eP
        return lhs == rhs
    
    def sign_file(self, filepath: str, private_key: int) -> tuple:
        """
        Sign a file's contents.
        
        Reads the entire file and signs its bytes.
        For large files, consider hashing first.
        
        Args:
            filepath: Path to file to sign
            private_key: Signer's private key
            
        Returns:
            (R, s) signature tuple
        """
        with open(filepath, 'rb') as f:
            data = f.read()
        
        # For large files, hash first to avoid memory issues
        # and to have a fixed-size message
        file_hash = hashlib.sha256(data).digest()
        
        return self.sign(file_hash, private_key)
    
    def verify_file(self, filepath: str, signature: tuple, public_key: ECPoint) -> bool:
        """
        Verify a file's signature.
        
        Args:
            filepath: Path to file
            signature: (R, s) signature tuple
            public_key: Signer's public key
            
        Returns:
            True if signature is valid
        """
        with open(filepath, 'rb') as f:
            data = f.read()
        
        file_hash = hashlib.sha256(data).digest()
        
        return self.verify(file_hash, signature, public_key)
    
    # =========================================================================
    # SERIALIZATION
    # =========================================================================
    
    def signature_to_bytes(self, signature: tuple) -> bytes:
        """
        Serialize signature to bytes.
        
        Format: R.x (32 bytes) || R.y (32 bytes) || s (32 bytes)
        Total: 96 bytes
        
        Args:
            signature: (R, s) tuple
            
        Returns:
            96-byte signature
        """
        R, s = signature
        return (
            R.x.to_bytes(32, 'big') +
            R.y.to_bytes(32, 'big') +
            s.to_bytes(32, 'big')
        )
    
    def signature_from_bytes(self, data: bytes) -> tuple:
        """
        Deserialize signature from bytes.
        
        Args:
            data: 96-byte serialized signature
            
        Returns:
            (R, s) tuple
        """
        if len(data) != 96:
            raise ValueError("Signature must be 96 bytes")
        
        R_x = int.from_bytes(data[:32], 'big')
        R_y = int.from_bytes(data[32:64], 'big')
        s = int.from_bytes(data[64:96], 'big')
        
        R = ECPoint(R_x, R_y, self.curve)
        
        return (R, s)
    
    def public_key_to_bytes(self, public_key: ECPoint) -> bytes:
        """Serialize public key to bytes."""
        return public_key.to_bytes()
    
    def public_key_from_bytes(self, data: bytes) -> ECPoint:
        """Deserialize public key from bytes."""
        return ECPoint.from_bytes(data, self.curve)
