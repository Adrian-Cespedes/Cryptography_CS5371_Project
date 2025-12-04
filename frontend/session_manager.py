"""Session manager for the password manager application."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional, Callable
from datetime import datetime

from shared.models import Vault, EncryptedBlob
from shared.crypto import CryptoManager, PepperManager

from .api_client import ApiClient, ApiError
from .backup_manager import BackupManager


@dataclass
class SessionState:
    """Current session state."""
    
    username: Optional[str] = None
    is_authenticated: bool = False
    vault: Optional[Vault] = None
    vault_key: Optional[bytes] = None
    master_password: Optional[str] = None  # Kept in memory for re-encryption
    is_offline: bool = False
    last_sync: Optional[datetime] = None


class SessionManager:
    """Manages application session, authentication, and vault operations."""
    
    def __init__(
        self,
        api_client: Optional[ApiClient] = None,
        backup_manager: Optional[BackupManager] = None,
    ):
        self.api = api_client or ApiClient()
        self.backup = backup_manager or BackupManager()
        self.pepper_manager = PepperManager()
        self._crypto: Optional[CryptoManager] = None
        self.state = SessionState()
        
        # Callbacks for state changes
        self._on_state_change: list[Callable[[SessionState], None]] = []
    
    @property
    def crypto(self) -> CryptoManager:
        """Get or create the CryptoManager with the loaded pepper.
        
        Raises:
            ValueError: If pepper is not available
        """
        if self._crypto is None:
            pepper = self.pepper_manager.load_pepper()
            if pepper is None:
                raise ValueError(
                    "Pepper not found. Please recover your seed phrase first."
                )
            self._crypto = CryptoManager(pepper)
        return self._crypto
    
    def reload_pepper(self):
        """Reload pepper from file (after recovery)."""
        self._crypto = None  # Clear cached crypto manager
    
    def add_state_listener(self, callback: Callable[[SessionState], None]):
        """Add a listener for state changes."""
        self._on_state_change.append(callback)
    
    def _notify_state_change(self):
        """Notify all listeners of state change."""
        for callback in self._on_state_change:
            callback(self.state)
    
    def check_server_connection(self) -> bool:
        """Check if server is reachable."""
        return self.api.health_check()
    
    def register(self, username: str, auth_password: str, master_password: str) -> bool:
        """Register a new user.
        
        Args:
            username: Username for the account
            auth_password: Password for server authentication
            master_password: Password for vault encryption
            
        Returns:
            True if successful
            
        Raises:
            ApiError: If registration fails
        """
        # Register with server
        self.api.register(username, auth_password)
        
        # Create new empty vault
        vault = Vault.create_new(name=f"{username}'s Vault")
        
        # Encrypt and save
        self.state.username = username
        self.state.master_password = master_password
        self.state.vault = vault
        self.state.is_authenticated = True
        
        # Save to server
        self._save_vault()
        
        self._notify_state_change()
        return True
    
    def login(self, username: str, auth_password: str, master_password: str) -> bool:
        """Login to an existing account.
        
        Args:
            username: Username
            auth_password: Password for server authentication
            master_password: Password for vault decryption
            
        Returns:
            True if successful
            
        Raises:
            ApiError: If login fails
            cryptography.exceptions.InvalidTag: If master password is wrong
        """
        try:
            # Try server login
            self.api.login(username, auth_password)
            self.state.is_offline = False
            
            # Get encrypted vault from server
            blob = self.api.get_vault()
            
            if blob:
                # Decrypt vault
                vault, vault_key = self.crypto.decrypt_encrypted_blob(blob, master_password)
                self.state.vault = vault
                self.state.vault_key = vault_key
                
                # Save backup
                self.backup.save_backup(username, blob)
            else:
                # New vault
                vault = Vault.create_new(name=f"{username}'s Vault")
                self.state.vault = vault
            
            self.state.username = username
            self.state.master_password = master_password
            self.state.is_authenticated = True
            self.state.last_sync = datetime.utcnow()
            
        except ApiError:
            # Try offline mode with backup
            return self.login_offline(username, master_password)
        
        self._notify_state_change()
        return True
    
    def login_offline(self, username: str, master_password: str) -> bool:
        """Login using local backup (offline mode).
        
        Args:
            username: Username
            master_password: Password for vault decryption
            
        Returns:
            True if successful
            
        Raises:
            ValueError: If no backup found
            cryptography.exceptions.InvalidTag: If master password is wrong
        """
        blob = self.backup.load_latest_backup(username)
        if not blob:
            raise ValueError("No local backup found. Cannot login offline.")
        
        # Decrypt vault
        vault, vault_key = self.crypto.decrypt_encrypted_blob(blob, master_password)
        
        self.state.username = username
        self.state.master_password = master_password
        self.state.vault = vault
        self.state.vault_key = vault_key
        self.state.is_authenticated = True
        self.state.is_offline = True
        
        self._notify_state_change()
        return True
    
    def login_from_file(self, backup_path: str, master_password: str) -> bool:
        """Login from a backup file.
        
        Args:
            backup_path: Path to backup file
            master_password: Password for vault decryption
            
        Returns:
            True if successful
        """
        username, blob = self.backup.load_backup(backup_path)
        
        # Decrypt vault
        vault, vault_key = self.crypto.decrypt_encrypted_blob(blob, master_password)
        
        self.state.username = username
        self.state.master_password = master_password
        self.state.vault = vault
        self.state.vault_key = vault_key
        self.state.is_authenticated = True
        self.state.is_offline = True
        
        self._notify_state_change()
        return True
    
    def logout(self):
        """Logout and clear session."""
        self.api.logout()
        self.state = SessionState()
        self._notify_state_change()
    
    def _save_vault(self):
        """Encrypt and save the vault to server and backup.
        
        This regenerates the salt for forward secrecy.
        """
        if not self.state.vault or not self.state.master_password:
            return
        
        # Create encrypted blob (generates new salt)
        blob, vault_key, _ = self.crypto.create_encrypted_blob(
            self.state.vault,
            self.state.master_password,
            self.state.vault_key,
        )
        self.state.vault_key = vault_key
        
        # Save backup locally first (in case server fails)
        self.backup.save_backup(self.state.username, blob)
        
        # Try to save to server
        if not self.state.is_offline:
            try:
                self.api.update_vault(blob)
                self.state.last_sync = datetime.utcnow()
            except ApiError:
                self.state.is_offline = True
        
        self._notify_state_change()
    
    def sync_vault(self) -> bool:
        """Sync vault with server.
        
        Returns:
            True if sync successful
        """
        if not self.state.is_authenticated:
            return False
        
        try:
            self._save_vault()
            self.state.is_offline = False
            self.state.last_sync = datetime.utcnow()
            self._notify_state_change()
            return True
        except ApiError:
            self.state.is_offline = True
            self._notify_state_change()
            return False
    
    # Vault Operations
    
    def add_item(
        self,
        title: str,
        username: str,
        password: str,
        url: str = "",
        notes: str = "",
    ) -> str:
        """Add a new item to the vault.
        
        Returns:
            The new item's ID
        """
        from shared.models import VaultItem
        
        item = VaultItem.create_new(
            title=title,
            username=username,
            password=password,
            url=url,
            notes=notes,
        )
        self.state.vault.add_item(item)
        self._save_vault()
        
        return item.id
    
    def update_item(self, item_id: str, **kwargs) -> bool:
        """Update an existing item.
        
        Returns:
            True if successful
        """
        success = self.state.vault.update_item(item_id, **kwargs)
        if success:
            self._save_vault()
        return success
    
    def delete_item(self, item_id: str) -> bool:
        """Delete an item from the vault.
        
        Returns:
            True if successful
        """
        success = self.state.vault.delete_item(item_id)
        if success:
            self._save_vault()
        return success
    
    def get_item(self, item_id: str):
        """Get an item by ID."""
        return self.state.vault.get_item(item_id)
    
    def get_all_items(self):
        """Get all items in the vault."""
        return self.state.vault.items if self.state.vault else []
    
    def search_items(self, query: str):
        """Search for items."""
        if not self.state.vault:
            return []
        return self.state.vault.search(query)
    
    def export_backup(self, path: str) -> str:
        """Export vault backup to a specific path.
        
        Args:
            path: Destination path
            
        Returns:
            Path to exported file
        """
        if not self.state.vault or not self.state.master_password:
            raise ValueError("No vault to export")
        
        blob, _, _ = self.crypto.create_encrypted_blob(
            self.state.vault,
            self.state.master_password,
            self.state.vault_key,
        )
        
        import json
        backup_data = {
            "version": 1,
            "username": self.state.username,
            "created_at": datetime.utcnow().isoformat(),
            "blob": blob.to_dict(),
        }
        
        with open(path, "w", encoding="utf-8") as f:
            json.dump(backup_data, f, indent=2)
        
        return path
