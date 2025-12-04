"""FastAPI Backend for Password Manager.

This backend only stores encrypted blobs - it has zero knowledge of user data.
"""

from .main import app

__all__ = ["app"]
