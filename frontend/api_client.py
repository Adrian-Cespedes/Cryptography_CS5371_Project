"""API client for communicating with the backend."""

from __future__ import annotations

import json
from typing import Optional, Tuple
from dataclasses import dataclass

import requests

from shared.models import EncryptedBlob


@dataclass
class ApiConfig:
    """API configuration."""
    
    base_url: str = "http://localhost:8000"
    timeout: int = 30


class ApiError(Exception):
    """API error with status code and message."""
    
    def __init__(self, message: str, status_code: int = 0):
        self.message = message
        self.status_code = status_code
        super().__init__(message)


class ApiClient:
    """Client for communicating with the password manager backend."""
    
    def __init__(self, config: Optional[ApiConfig] = None):
        self.config = config or ApiConfig()
        self._token: Optional[str] = None
        self._username: Optional[str] = None
    
    @property
    def is_authenticated(self) -> bool:
        """Check if the client has a valid token."""
        return self._token is not None
    
    @property
    def username(self) -> Optional[str]:
        """Get the current username."""
        return self._username
    
    def _headers(self) -> dict:
        """Get request headers."""
        headers = {"Content-Type": "application/json"}
        if self._token:
            headers["Authorization"] = f"Bearer {self._token}"
        return headers
    
    def _request(
        self,
        method: str,
        endpoint: str,
        data: Optional[dict] = None,
        require_auth: bool = False,
    ) -> dict:
        """Make an HTTP request to the API.
        
        Args:
            method: HTTP method (GET, POST, PUT, DELETE)
            endpoint: API endpoint (e.g., "/auth/login")
            data: Request body data
            require_auth: Whether authentication is required
            
        Returns:
            Response JSON data
            
        Raises:
            ApiError: If the request fails
        """
        if require_auth and not self._token:
            raise ApiError("Authentication required", status_code=401)
        
        url = f"{self.config.base_url}{endpoint}"
        
        try:
            response = requests.request(
                method=method,
                url=url,
                headers=self._headers(),
                json=data,
                timeout=self.config.timeout,
            )
            
            if response.status_code >= 400:
                error_data = response.json() if response.text else {}
                detail = error_data.get("detail", f"Request failed: {response.status_code}")
                raise ApiError(detail, status_code=response.status_code)
            
            return response.json() if response.text else {}
            
        except requests.exceptions.ConnectionError:
            raise ApiError("Cannot connect to server. Please check if the server is running.")
        except requests.exceptions.Timeout:
            raise ApiError("Request timed out. Please try again.")
        except requests.exceptions.RequestException as e:
            raise ApiError(f"Request failed: {str(e)}")
    
    def health_check(self) -> bool:
        """Check if the server is healthy.
        
        Returns:
            True if server is healthy, False otherwise
        """
        try:
            self._request("GET", "/health")
            return True
        except ApiError:
            return False
    
    def register(self, username: str, password: str) -> Tuple[str, str]:
        """Register a new user.
        
        Args:
            username: Username for the new account
            password: Password for server authentication
            
        Returns:
            Tuple of (access_token, username)
        """
        data = {"username": username, "password": password}
        response = self._request("POST", "/auth/register", data=data)
        
        self._token = response["access_token"]
        self._username = response["username"]
        
        return self._token, self._username
    
    def login(self, username: str, password: str) -> Tuple[str, str]:
        """Login to an existing account.
        
        Args:
            username: Username
            password: Password for server authentication
            
        Returns:
            Tuple of (access_token, username)
        """
        data = {"username": username, "password": password}
        response = self._request("POST", "/auth/login", data=data)
        
        self._token = response["access_token"]
        self._username = response["username"]
        
        return self._token, self._username
    
    def logout(self):
        """Clear authentication state."""
        self._token = None
        self._username = None
    
    def get_user_info(self) -> dict:
        """Get current user information.
        
        Returns:
            User info dict with username, created_at, has_vault
        """
        return self._request("GET", "/auth/me", require_auth=True)
    
    def get_vault(self) -> Optional[EncryptedBlob]:
        """Get the user's encrypted vault.
        
        Returns:
            EncryptedBlob if vault exists, None otherwise
        """
        response = self._request("GET", "/vault", require_auth=True)
        blob_json = response.get("encrypted_blob")
        
        if blob_json:
            return EncryptedBlob.from_json(blob_json)
        return None
    
    def update_vault(self, blob: EncryptedBlob) -> bool:
        """Update the user's encrypted vault.
        
        Args:
            blob: The encrypted vault blob
            
        Returns:
            True if successful
        """
        data = {"encrypted_blob": blob.to_json()}
        self._request("PUT", "/vault", data=data, require_auth=True)
        return True
    
    def delete_vault(self) -> bool:
        """Delete the user's vault.
        
        Returns:
            True if successful
        """
        self._request("DELETE", "/vault", require_auth=True)
        return True
    
    def delete_account(self) -> bool:
        """Delete the user's account.
        
        Returns:
            True if successful
        """
        self._request("DELETE", "/account", require_auth=True)
        self.logout()
        return True
