"""Local backup manager for encrypted vault data."""

from __future__ import annotations

import json
import os
from datetime import datetime
from pathlib import Path
from typing import Optional, List

from shared.models import EncryptedBlob


class BackupManager:
    """Manages local backups of encrypted vault data."""
    
    def __init__(self, backup_dir: Optional[str] = None):
        """Initialize the backup manager.
        
        Args:
            backup_dir: Custom backup directory path. If None, uses default.
        """
        if backup_dir:
            self.backup_dir = Path(backup_dir)
        else:
            # Default to ~/.proton_vault/backups/
            home = Path.home()
            self.backup_dir = home / ".proton_vault" / "backups"
        
        # Ensure backup directory exists
        self.backup_dir.mkdir(parents=True, exist_ok=True)
    
    def _get_backup_filename(self, username: str) -> str:
        """Generate a backup filename with timestamp.
        
        Args:
            username: The username for the backup
            
        Returns:
            Backup filename
        """
        timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        return f"vault_{username}_{timestamp}.backup"
    
    def _get_latest_backup_path(self, username: str) -> Optional[Path]:
        """Get the path to the latest backup for a user.
        
        Args:
            username: The username to find backups for
            
        Returns:
            Path to latest backup or None if no backups exist
        """
        pattern = f"vault_{username}_*.backup"
        backups = sorted(self.backup_dir.glob(pattern), reverse=True)
        return backups[0] if backups else None
    
    def save_backup(self, username: str, blob: EncryptedBlob) -> str:
        """Save an encrypted vault backup.
        
        This saves the encrypted blob to a local file. The data is already
        encrypted, so no additional encryption is needed.
        
        Args:
            username: The username for the backup
            blob: The encrypted vault blob
            
        Returns:
            Path to the saved backup file
        """
        filename = self._get_backup_filename(username)
        backup_path = self.backup_dir / filename
        
        # Create backup data structure
        backup_data = {
            "version": 1,
            "username": username,
            "created_at": datetime.utcnow().isoformat(),
            "blob": blob.to_dict(),
        }
        
        # Write to file
        with open(backup_path, "w", encoding="utf-8") as f:
            json.dump(backup_data, f, indent=2)
        
        # Also maintain a "latest" symlink/copy for quick access
        latest_path = self.backup_dir / f"vault_{username}_latest.backup"
        with open(latest_path, "w", encoding="utf-8") as f:
            json.dump(backup_data, f, indent=2)
        
        return str(backup_path)
    
    def load_backup(self, backup_path: str) -> tuple[str, EncryptedBlob]:
        """Load an encrypted vault from a backup file.
        
        Args:
            backup_path: Path to the backup file
            
        Returns:
            Tuple of (username, encrypted_blob)
            
        Raises:
            FileNotFoundError: If backup file doesn't exist
            ValueError: If backup file is invalid
        """
        path = Path(backup_path)
        if not path.exists():
            raise FileNotFoundError(f"Backup file not found: {backup_path}")
        
        with open(path, "r", encoding="utf-8") as f:
            backup_data = json.load(f)
        
        # Validate backup structure
        if "blob" not in backup_data or "username" not in backup_data:
            raise ValueError("Invalid backup file format")
        
        username = backup_data["username"]
        blob = EncryptedBlob.from_dict(backup_data["blob"])
        
        return username, blob
    
    def load_latest_backup(self, username: str) -> Optional[EncryptedBlob]:
        """Load the latest backup for a user.
        
        Args:
            username: The username to find backups for
            
        Returns:
            EncryptedBlob if found, None otherwise
        """
        latest_path = self.backup_dir / f"vault_{username}_latest.backup"
        
        if not latest_path.exists():
            return None
        
        try:
            _, blob = self.load_backup(str(latest_path))
            return blob
        except (ValueError, json.JSONDecodeError):
            return None
    
    def list_backups(self, username: Optional[str] = None) -> List[dict]:
        """List available backups.
        
        Args:
            username: Optional username to filter by
            
        Returns:
            List of backup info dicts with path, username, created_at
        """
        if username:
            pattern = f"vault_{username}_*.backup"
        else:
            pattern = "vault_*_*.backup"
        
        backups = []
        for backup_path in sorted(self.backup_dir.glob(pattern), reverse=True):
            # Skip "latest" symlinks
            if "_latest" in backup_path.name:
                continue
            
            try:
                with open(backup_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                
                backups.append({
                    "path": str(backup_path),
                    "filename": backup_path.name,
                    "username": data.get("username", "unknown"),
                    "created_at": data.get("created_at", "unknown"),
                })
            except (json.JSONDecodeError, IOError):
                continue
        
        return backups
    
    def delete_backup(self, backup_path: str) -> bool:
        """Delete a backup file.
        
        Args:
            backup_path: Path to the backup file
            
        Returns:
            True if deleted, False otherwise
        """
        path = Path(backup_path)
        if path.exists() and path.parent == self.backup_dir:
            path.unlink()
            return True
        return False
    
    def cleanup_old_backups(self, username: str, keep_count: int = 5) -> int:
        """Remove old backups, keeping only the most recent ones.
        
        Args:
            username: The username to cleanup backups for
            keep_count: Number of backups to keep
            
        Returns:
            Number of backups deleted
        """
        pattern = f"vault_{username}_*.backup"
        backups = sorted(self.backup_dir.glob(pattern), reverse=True)
        
        # Filter out "latest" files
        backups = [b for b in backups if "_latest" not in b.name]
        
        deleted = 0
        if len(backups) > keep_count:
            for backup in backups[keep_count:]:
                backup.unlink()
                deleted += 1
        
        return deleted
