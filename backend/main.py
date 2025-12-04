"""FastAPI main application for the Password Manager backend.

This is a zero-knowledge backend - it only stores encrypted blobs
and has no ability to decrypt user data.
"""

from __future__ import annotations

from contextlib import asynccontextmanager
from datetime import datetime

from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session

from .database import init_db, get_db, User
from .schemas import (
    UserCreate,
    UserLogin,
    TokenResponse,
    BlobUpdate,
    BlobResponse,
    UserResponse,
    MessageResponse,
)
from .auth import (
    create_access_token,
    get_current_user,
    generate_auth_salt,
    hash_auth_password,
    verify_auth_password,
)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan handler."""
    # Startup: initialize database
    init_db()
    yield
    # Shutdown: cleanup if needed


app = FastAPI(
    title="Proton Vault API",
    description="Zero-knowledge password manager backend",
    version="1.0.0",
    lifespan=lifespan,
)

# CORS middleware for frontend communication
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # In production, restrict this
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/", response_model=MessageResponse)
async def root():
    """Root endpoint - health check."""
    return MessageResponse(message="Proton Vault API is running")


@app.get("/health", response_model=MessageResponse)
async def health_check():
    """Health check endpoint."""
    return MessageResponse(message="healthy")


# ============== Authentication Endpoints ==============


@app.post("/auth/register", response_model=TokenResponse, status_code=status.HTTP_201_CREATED)
async def register(user_data: UserCreate, db: Session = Depends(get_db)):
    """Register a new user.
    
    The password here is used for server authentication only.
    The master password for encryption is handled client-side.
    """
    # Check if username already exists
    existing_user = db.query(User).filter(User.username == user_data.username).first()
    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Username already registered",
        )
    
    # Generate salt and hash password
    auth_salt = generate_auth_salt()
    password_hash = hash_auth_password(user_data.password, auth_salt)
    
    # Create user
    user = User(
        username=user_data.username,
        password_hash=password_hash,
        auth_salt=auth_salt,
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    
    # Generate token
    token = create_access_token(user.username)
    
    return TokenResponse(
        access_token=token,
        username=user.username,
    )


@app.post("/auth/login", response_model=TokenResponse)
async def login(user_data: UserLogin, db: Session = Depends(get_db)):
    """Login and get an access token."""
    # Find user
    user = db.query(User).filter(User.username == user_data.username).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password",
        )
    
    # Verify password
    if not verify_auth_password(user_data.password, user.auth_salt, user.password_hash):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password",
        )
    
    # Generate token
    token = create_access_token(user.username)
    
    return TokenResponse(
        access_token=token,
        username=user.username,
    )


@app.get("/auth/me", response_model=UserResponse)
async def get_me(current_user: User = Depends(get_current_user)):
    """Get current user info."""
    return UserResponse(
        username=current_user.username,
        created_at=current_user.created_at,
        has_vault=current_user.encrypted_blob is not None,
    )


# ============== Vault/Blob Endpoints ==============


@app.get("/vault", response_model=BlobResponse)
async def get_vault(current_user: User = Depends(get_current_user)):
    """Get the user's encrypted vault blob.
    
    The server cannot decrypt this data - only the client with
    the master password can.
    """
    return BlobResponse(
        encrypted_blob=current_user.encrypted_blob,
        updated_at=current_user.updated_at,
    )


@app.put("/vault", response_model=MessageResponse)
async def update_vault(
    blob_data: BlobUpdate,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Update the user's encrypted vault blob.
    
    The client encrypts the vault locally and sends the encrypted
    blob to the server for storage.
    """
    current_user.encrypted_blob = blob_data.encrypted_blob
    current_user.updated_at = datetime.utcnow()
    db.commit()
    
    return MessageResponse(message="Vault updated successfully")


@app.delete("/vault", response_model=MessageResponse)
async def delete_vault(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Delete the user's vault (dangerous operation)."""
    current_user.encrypted_blob = None
    current_user.updated_at = datetime.utcnow()
    db.commit()
    
    return MessageResponse(message="Vault deleted successfully")


# ============== Account Management ==============


@app.delete("/account", response_model=MessageResponse)
async def delete_account(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Delete user account and all data."""
    db.delete(current_user)
    db.commit()
    
    return MessageResponse(message="Account deleted successfully")


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
