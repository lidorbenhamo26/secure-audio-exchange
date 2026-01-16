# Cryptographic Utilities
# Allowed imports only: hashlib, secrets, os

import secrets
import hashlib


def rotate_left_32(x: int, n: int) -> int:
    """Rotate a 32-bit integer left by n bits."""
    return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF


def rotate_left_64(x: int, n: int) -> int:
    """Rotate a 64-bit integer left by n bits."""
    return ((x << n) | (x >> (64 - n))) & 0xFFFFFFFFFFFFFFFF


def bytes_to_int(b: bytes) -> int:
    """Convert bytes to integer (big-endian)."""
    return int.from_bytes(b, 'big')


def int_to_bytes(n: int, length: int) -> bytes:
    """Convert integer to bytes (big-endian)."""
    return n.to_bytes(length, 'big')


def xor_bytes(a: bytes, b: bytes) -> bytes:
    """XOR two byte strings of equal length."""
    return bytes(x ^ y for x, y in zip(a, b))


def extended_gcd(a: int, b: int) -> tuple:
    """
    Extended Euclidean Algorithm.
    Returns (gcd, x, y) such that a*x + b*y = gcd.
    """
    if a == 0:
        return b, 0, 1
    gcd, x1, y1 = extended_gcd(b % a, a)
    x = y1 - (b // a) * x1
    y = x1
    return gcd, x, y


def mod_inverse(a: int, p: int) -> int:
    """
    Compute modular multiplicative inverse of a modulo p.
    Uses Extended Euclidean Algorithm.
    """
    if a < 0:
        a = a % p
    g, x, _ = extended_gcd(a, p)
    if g != 1:
        raise ValueError("No modular inverse exists")
    return x % p


def secure_random_bytes(n: int) -> bytes:
    """Generate n cryptographically secure random bytes."""
    return secrets.token_bytes(n)


def secure_random_below(n: int) -> int:
    """Generate a random integer in [0, n-1]."""
    return secrets.randbelow(n)
