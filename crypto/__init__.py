# crypto/__init__.py
"""
Secure Audio Data Exchange System - Crypto Module

This module provides low-level cryptographic primitives:
- Camellia-128 symmetric cipher (OFB mode)
- Elliptic Curve Cryptography (NIST P-256)
- Schnorr Digital Signatures

NO HIGH-LEVEL CRYPTO LIBRARIES USED.
Only hashlib and secrets are imported.
"""

from .camellia import Camellia
from .ecc import ECC, ECPoint
from .schnorr import Schnorr

__all__ = ['Camellia', 'ECC', 'ECPoint', 'Schnorr']
