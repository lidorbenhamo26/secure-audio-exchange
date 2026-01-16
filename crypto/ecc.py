"""
Elliptic Curve Cryptography Implementation

Implements:
- ECPoint class for curve point representation
- Point addition, doubling, and scalar multiplication
- NIST P-256 curve parameters
- ECDH key exchange

NO external crypto libraries used. Only standard library.
"""

import hashlib
from .utils import mod_inverse, secure_random_below


# =============================================================================
# NIST P-256 (secp256r1) CURVE PARAMETERS
# =============================================================================

# These are the official NIST P-256 parameters from FIPS 186-4
NIST_P256 = {
    # Prime field modulus
    'p': 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF,
    
    # Curve coefficients: y² = x³ + ax + b
    'a': 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC,
    'b': 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B,
    
    # Base point (generator) G coordinates
    'Gx': 0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296,
    'Gy': 0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5,
    
    # Order of the base point (number of points in subgroup)
    'n': 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551,
    
    # Cofactor
    'h': 1,
    
    # Curve name for reference
    'name': 'NIST P-256 (secp256r1)'
}


class ECPoint:
    """
    Represents a point on an elliptic curve.
    
    Supports the point at infinity (identity element) when x=None, y=None.
    The curve parameters are stored as a reference for operations.
    """
    
    def __init__(self, x: int, y: int, curve: dict):
        """
        Initialize a point on the curve.
        
        Args:
            x: X-coordinate (None for point at infinity)
            y: Y-coordinate (None for point at infinity)
            curve: Curve parameters dict containing p, a, b, n, etc.
        """
        self.x = x
        self.y = y
        self.curve = curve
        self.infinity = (x is None and y is None)
    
    @staticmethod
    def point_at_infinity(curve: dict) -> 'ECPoint':
        """Create the point at infinity (identity element)."""
        return ECPoint(None, None, curve)
    
    def is_on_curve(self) -> bool:
        """
        Verify that this point lies on the curve.
        
        Checks: y² ≡ x³ + ax + b (mod p)
        """
        if self.infinity:
            return True
        
        p = self.curve['p']
        a = self.curve['a']
        b = self.curve['b']
        
        lhs = (self.y * self.y) % p
        rhs = (pow(self.x, 3, p) + a * self.x + b) % p
        
        return lhs == rhs
    
    def __eq__(self, other: 'ECPoint') -> bool:
        """Check if two points are equal."""
        if not isinstance(other, ECPoint):
            return False
        if self.infinity and other.infinity:
            return True
        if self.infinity or other.infinity:
            return False
        return self.x == other.x and self.y == other.y
    
    def __repr__(self) -> str:
        if self.infinity:
            return "ECPoint(infinity)"
        return f"ECPoint(x={hex(self.x)}, y={hex(self.y)})"
    
    def negate(self) -> 'ECPoint':
        """Return the negation of this point: -P = (x, -y mod p)."""
        if self.infinity:
            return ECPoint.point_at_infinity(self.curve)
        return ECPoint(self.x, (-self.y) % self.curve['p'], self.curve)
    
    def to_bytes(self) -> bytes:
        """
        Serialize point to bytes (uncompressed format).
        Format: 0x04 || x (32 bytes) || y (32 bytes)
        """
        if self.infinity:
            return b'\x00'
        return b'\x04' + self.x.to_bytes(32, 'big') + self.y.to_bytes(32, 'big')
    
    @staticmethod
    def from_bytes(data: bytes, curve: dict) -> 'ECPoint':
        """Deserialize point from bytes."""
        if data == b'\x00':
            return ECPoint.point_at_infinity(curve)
        if data[0] != 0x04:
            raise ValueError("Only uncompressed point format supported")
        x = int.from_bytes(data[1:33], 'big')
        y = int.from_bytes(data[33:65], 'big')
        return ECPoint(x, y, curve)


class ECC:
    """
    Elliptic Curve Cryptography operations.
    
    Provides:
    - Point arithmetic (add, double, multiply)
    - ECDH key generation and shared secret computation
    
    Usage:
        ecc = ECC()  # Uses NIST P-256 by default
        private_key, public_key = ecc.generate_keypair()
        shared_secret = ecc.compute_shared_secret(my_private, their_public)
    """
    
    def __init__(self, curve: dict = None):
        """
        Initialize ECC with curve parameters.
        
        Args:
            curve: Curve parameters dict (defaults to NIST P-256)
        """
        self.curve = curve if curve is not None else NIST_P256
        
        # Create generator point
        self.G = ECPoint(
            self.curve['Gx'],
            self.curve['Gy'],
            self.curve
        )
        
        # Verify generator is on curve
        if not self.G.is_on_curve():
            raise ValueError("Generator point not on curve")
    
    # =========================================================================
    # POINT ARITHMETIC
    # =========================================================================
    
    def point_add(self, P: ECPoint, Q: ECPoint) -> ECPoint:
        """
        Add two points on the elliptic curve.
        
        R = P + Q using the standard addition formula:
        - If P = O (infinity): return Q
        - If Q = O (infinity): return P
        - If P = -Q: return O
        - If P = Q: use point_double
        - Otherwise:
            λ = (y₂ - y₁) / (x₂ - x₁) mod p
            x₃ = λ² - x₁ - x₂ mod p
            y₃ = λ(x₁ - x₃) - y₁ mod p
        
        Args:
            P: First point
            Q: Second point
            
        Returns:
            Sum point R = P + Q
        """
        # Handle point at infinity (identity element)
        if P.infinity:
            return Q
        if Q.infinity:
            return P
        
        p = self.curve['p']
        
        # Check if P = -Q (result is point at infinity)
        if P.x == Q.x:
            if (P.y + Q.y) % p == 0:
                return ECPoint.point_at_infinity(self.curve)
            else:
                # P = Q, use doubling
                return self.point_double(P)
        
        # Standard addition formula
        # λ = (y₂ - y₁) * (x₂ - x₁)^(-1) mod p
        delta_y = (Q.y - P.y) % p
        delta_x = (Q.x - P.x) % p
        lam = (delta_y * mod_inverse(delta_x, p)) % p
        
        # x₃ = λ² - x₁ - x₂ mod p
        x3 = (lam * lam - P.x - Q.x) % p
        
        # y₃ = λ(x₁ - x₃) - y₁ mod p
        y3 = (lam * (P.x - x3) - P.y) % p
        
        return ECPoint(x3, y3, self.curve)
    
    def point_double(self, P: ECPoint) -> ECPoint:
        """
        Double a point on the elliptic curve.
        
        R = 2P using the doubling formula:
            λ = (3x₁² + a) / (2y₁) mod p
            x₃ = λ² - 2x₁ mod p
            y₃ = λ(x₁ - x₃) - y₁ mod p
        
        Args:
            P: Point to double
            
        Returns:
            Doubled point R = 2P
        """
        if P.infinity or P.y == 0:
            return ECPoint.point_at_infinity(self.curve)
        
        p = self.curve['p']
        a = self.curve['a']
        
        # λ = (3x² + a) * (2y)^(-1) mod p
        numerator = (3 * P.x * P.x + a) % p
        denominator = (2 * P.y) % p
        lam = (numerator * mod_inverse(denominator, p)) % p
        
        # x₃ = λ² - 2x₁ mod p
        x3 = (lam * lam - 2 * P.x) % p
        
        # y₃ = λ(x₁ - x₃) - y₁ mod p
        y3 = (lam * (P.x - x3) - P.y) % p
        
        return ECPoint(x3, y3, self.curve)
    
    def scalar_multiply(self, k: int, P: ECPoint) -> ECPoint:
        """
        Scalar multiplication using the Double-and-Add algorithm.
        
        Computes Q = kP where k is a scalar and P is a point.
        
        Algorithm (left-to-right binary method):
        1. Initialize R = O (point at infinity)
        2. For each bit of k from MSB to LSB:
           a. R = 2R (double)
           b. If bit is 1: R = R + P (add)
        3. Return R
        
        Time complexity: O(log k) point operations
        
        Args:
            k: Scalar multiplier (integer)
            P: Point to multiply
            
        Returns:
            Result point Q = kP
        """
        if k == 0 or P.infinity:
            return ECPoint.point_at_infinity(self.curve)
        
        # Handle negative k
        if k < 0:
            k = -k
            P = P.negate()
        
        # Reduce k modulo n for efficiency
        k = k % self.curve['n']
        if k == 0:
            return ECPoint.point_at_infinity(self.curve)
        
        # Double-and-Add algorithm
        R = ECPoint.point_at_infinity(self.curve)
        
        # Process bits from MSB to LSB
        for i in range(k.bit_length() - 1, -1, -1):
            R = self.point_double(R)
            if (k >> i) & 1:
                R = self.point_add(R, P)
        
        return R
    
    # =========================================================================
    # ECDH KEY EXCHANGE
    # =========================================================================
    
    def generate_keypair(self) -> tuple:
        """
        Generate an ECDH key pair.
        
        Private key: Random integer d in [1, n-1]
        Public key: Point Q = dG
        
        Returns:
            (private_key, public_key) tuple where:
                - private_key is an integer
                - public_key is an ECPoint
        """
        n = self.curve['n']
        
        # Generate random private key in [1, n-1]
        private_key = secure_random_below(n - 1) + 1
        
        # Compute public key Q = dG
        public_key = self.scalar_multiply(private_key, self.G)
        
        # Verify public key is on curve (sanity check)
        if not public_key.is_on_curve():
            raise RuntimeError("Generated public key not on curve")
        
        return private_key, public_key
    
    def compute_shared_secret(self, private_key: int, other_public_key: ECPoint) -> bytes:
        """
        Compute ECDH shared secret.
        
        The shared secret is computed as:
            S = d_A * Q_B = d_A * d_B * G
        
        Both parties arrive at the same point S because:
            d_A * Q_B = d_A * (d_B * G) = d_B * (d_A * G) = d_B * Q_A
        
        The x-coordinate of S is hashed with SHA-256 to produce
        a uniformly distributed key.
        
        Args:
            private_key: Your private key (integer)
            other_public_key: Other party's public key (ECPoint)
            
        Returns:
            32-byte shared secret (SHA-256 hash of x-coordinate)
        """
        # Verify the other public key is on our curve
        if not other_public_key.is_on_curve():
            raise ValueError("Other party's public key is not on the curve")
        
        # Compute shared point S = private_key * other_public_key
        shared_point = self.scalar_multiply(private_key, other_public_key)
        
        # The shared point should not be the point at infinity
        if shared_point.infinity:
            raise ValueError("Shared secret computation resulted in point at infinity")
        
        # Use x-coordinate as shared secret, hash for uniformity
        x_bytes = shared_point.x.to_bytes(32, 'big')
        
        # Apply SHA-256 to ensure uniform distribution
        return hashlib.sha256(x_bytes).digest()
    
    def derive_camellia_key(self, shared_secret: bytes) -> bytes:
        """
        Derive a 128-bit Camellia key from the ECDH shared secret.
        
        Takes the first 16 bytes of SHA-256(shared_secret).
        
        Args:
            shared_secret: 32-byte ECDH shared secret
            
        Returns:
            16-byte Camellia key
        """
        # Note: shared_secret is already hashed in compute_shared_secret
        # For additional key separation, we could hash again with a label
        return shared_secret[:16]
    
    # =========================================================================
    # SERIALIZATION
    # =========================================================================
    
    def public_key_to_bytes(self, public_key: ECPoint) -> bytes:
        """Serialize public key to bytes."""
        return public_key.to_bytes()
    
    def public_key_from_bytes(self, data: bytes) -> ECPoint:
        """Deserialize public key from bytes."""
        return ECPoint.from_bytes(data, self.curve)
