"""Pydantic schemas for API request/response validation."""

from __future__ import annotations

from datetime import datetime
from typing import Optional

from pydantic import BaseModel, Field


class UserCreate(BaseModel):
    """Schema for user registration."""

    username: str = Field(..., min_length=3, max_length=50)
    password: str = Field(..., min_length=8)


class UserLogin(BaseModel):
    """Schema for user login."""

    username: str
    password: str


class TokenResponse(BaseModel):
    """Schema for JWT token response."""

    access_token: str
    token_type: str = "bearer"
    username: str


class BlobUpdate(BaseModel):
    """Schema for updating the encrypted blob."""

    encrypted_blob: str  # JSON string of EncryptedBlob


class BlobResponse(BaseModel):
    """Schema for blob response."""

    encrypted_blob: Optional[str] = None
    updated_at: Optional[datetime] = None


class UserResponse(BaseModel):
    """Schema for user info response."""

    username: str
    created_at: datetime
    has_vault: bool


class MessageResponse(BaseModel):
    """Generic message response."""

    message: str
    success: bool = True


class ErrorResponse(BaseModel):
    """Error response schema."""

    detail: str
    error_code: Optional[str] = None
