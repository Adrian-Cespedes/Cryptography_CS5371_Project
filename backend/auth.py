"""Authentication utilities for the backend."""

from __future__ import annotations

import base64
import os
import secrets
from datetime import datetime, timedelta
from typing import Optional

from jose import JWTError, jwt
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.orm import Session

from .database import get_db, User

# JWT Configuration
SECRET_KEY = os.environ.get("PM_SECRET_KEY", secrets.token_hex(32))
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_HOURS = 24

# Security scheme
security = HTTPBearer()


def create_access_token(username: str) -> str:
    """Create a JWT access token.
    
    Args:
        username: The username to encode in the token
        
    Returns:
        Encoded JWT token
    """
    expire = datetime.utcnow() + timedelta(hours=ACCESS_TOKEN_EXPIRE_HOURS)
    to_encode = {
        "sub": username,
        "exp": expire,
        "iat": datetime.utcnow(),
    }
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


def verify_token(token: str) -> Optional[str]:
    """Verify a JWT token and return the username.
    
    Args:
        token: The JWT token to verify
        
    Returns:
        Username if valid, None otherwise
    """
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            return None
        return username
    except JWTError:
        return None


async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db: Session = Depends(get_db),
) -> User:
    """Dependency to get the current authenticated user.
    
    Args:
        credentials: The HTTP authorization credentials
        db: Database session
        
    Returns:
        The authenticated User object
        
    Raises:
        HTTPException: If authentication fails
    """
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid authentication credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    
    token = credentials.credentials
    username = verify_token(token)
    
    if username is None:
        raise credentials_exception
    
    user = db.query(User).filter(User.username == username).first()
    if user is None:
        raise credentials_exception
    
    return user


def generate_auth_salt() -> str:
    """Generate a salt for password hashing.
    
    Returns:
        Base64-encoded salt
    """
    return base64.b64encode(secrets.token_bytes(16)).decode("ascii")


def hash_auth_password(password: str, salt: str) -> str:
    """Hash a password for authentication using Argon2id.
    
    This is used for server-side authentication, separate from
    the master key derivation used for encryption.
    
    Args:
        password: The password to hash
        salt: The salt (base64-encoded)
        
    Returns:
        Base64-encoded hash
    """
    from argon2.low_level import hash_secret_raw, Type
    
    salt_bytes = base64.b64decode(salt)
    # Use a different pepper for auth (separation of concerns)
    auth_pepper = b"ProtonVaultAuthPepper2024Secret!"
    password_bytes = password.encode("utf-8") + auth_pepper
    
    hash_bytes = hash_secret_raw(
        secret=password_bytes,
        salt=salt_bytes,
        time_cost=3,
        memory_cost=65536,
        parallelism=4,
        hash_len=32,
        type=Type.ID,
    )
    
    return base64.b64encode(hash_bytes).decode("ascii")


def verify_auth_password(password: str, salt: str, stored_hash: str) -> bool:
    """Verify a password against a stored hash.
    
    Args:
        password: The password to verify
        salt: The salt (base64-encoded)
        stored_hash: The stored hash to compare against
        
    Returns:
        True if password matches, False otherwise
    """
    computed_hash = hash_auth_password(password, salt)
    return secrets.compare_digest(computed_hash, stored_hash)
