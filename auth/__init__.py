"""
Authentication Module

Provides paper-based authentication using PBKDF2-HMAC-SHA256.
"""

from .paper_auth import PaperAuth, quick_auth

__all__ = ['PaperAuth', 'quick_auth']

