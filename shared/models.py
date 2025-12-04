"""Data models shared between frontend and backend."""

from __future__ import annotations

import json
from dataclasses import dataclass, field, asdict
from datetime import datetime
from typing import List, Optional
import uuid


@dataclass
class VaultItem:
    """An individual credential/item stored inside a vault."""

    id: str
    title: str
    username: str
    password: str
    url: str = ""
    notes: str = ""
    created_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    modified_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())

    @classmethod
    def create_new(
        cls,
        title: str,
        username: str,
        password: str,
        url: str = "",
        notes: str = "",
    ) -> "VaultItem":
        """Create a new vault item with auto-generated ID and timestamps."""
        now = datetime.utcnow().isoformat()
        return cls(
            id=str(uuid.uuid4()),
            title=title,
            username=username,
            password=password,
            url=url,
            notes=notes,
            created_at=now,
            modified_at=now,
        )

    def update(self, **kwargs) -> "VaultItem":
        """Return a new VaultItem with updated fields."""
        data = asdict(self)
        data.update(kwargs)
        data["modified_at"] = datetime.utcnow().isoformat()
        return VaultItem(**data)

    def to_dict(self) -> dict:
        """Convert to dictionary."""
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict) -> "VaultItem":
        """Create from dictionary."""
        return cls(**data)


@dataclass
class Vault:
    """A collection of vault items for a user."""

    id: str
    name: str
    items: List[VaultItem] = field(default_factory=list)
    created_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    modified_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())

    @classmethod
    def create_new(cls, name: str = "My Vault") -> "Vault":
        """Create a new empty vault."""
        now = datetime.utcnow().isoformat()
        return cls(
            id=str(uuid.uuid4()),
            name=name,
            items=[],
            created_at=now,
            modified_at=now,
        )

    def add_item(self, item: VaultItem) -> None:
        """Add an item to the vault."""
        self.items.append(item)
        self.modified_at = datetime.utcnow().isoformat()

    def update_item(self, item_id: str, **kwargs) -> bool:
        """Update an existing item."""
        for i, item in enumerate(self.items):
            if item.id == item_id:
                self.items[i] = item.update(**kwargs)
                self.modified_at = datetime.utcnow().isoformat()
                return True
        return False

    def delete_item(self, item_id: str) -> bool:
        """Delete an item from the vault."""
        for i, item in enumerate(self.items):
            if item.id == item_id:
                del self.items[i]
                self.modified_at = datetime.utcnow().isoformat()
                return True
        return False

    def get_item(self, item_id: str) -> Optional[VaultItem]:
        """Get an item by ID."""
        for item in self.items:
            if item.id == item_id:
                return item
        return None

    def search(self, query: str) -> List[VaultItem]:
        """Search items by title or username."""
        query_lower = query.lower()
        return [
            item
            for item in self.items
            if query_lower in item.title.lower()
            or query_lower in item.username.lower()
            or query_lower in item.url.lower()
        ]

    def to_dict(self) -> dict:
        """Convert to dictionary."""
        return {
            "id": self.id,
            "name": self.name,
            "items": [item.to_dict() for item in self.items],
            "created_at": self.created_at,
            "modified_at": self.modified_at,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "Vault":
        """Create from dictionary."""
        items = [VaultItem.from_dict(item) for item in data.get("items", [])]
        return cls(
            id=data["id"],
            name=data["name"],
            items=items,
            created_at=data.get("created_at", datetime.utcnow().isoformat()),
            modified_at=data.get("modified_at", datetime.utcnow().isoformat()),
        )

    def to_json(self) -> str:
        """Serialize to JSON string."""
        return json.dumps(self.to_dict(), ensure_ascii=False)

    @classmethod
    def from_json(cls, json_str: str) -> "Vault":
        """Deserialize from JSON string."""
        return cls.from_dict(json.loads(json_str))


@dataclass
class EncryptedBlob:
    """Encrypted vault data with metadata for storage/transmission."""

    # Encrypted vault data (base64 encoded)
    ciphertext: str
    # Initialization vector (base64 encoded)
    iv: str
    # Authentication tag (base64 encoded)
    auth_tag: str
    # Salt used for key derivation (base64 encoded)
    salt: str
    # Encrypted vault key (base64 encoded) - encrypted with master key
    encrypted_vault_key: str
    # IV for vault key encryption (base64 encoded)
    vault_key_iv: str
    # Auth tag for vault key encryption (base64 encoded)
    vault_key_auth_tag: str
    # Timestamp of last modification
    modified_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    # Version for future compatibility
    version: int = 1

    def to_dict(self) -> dict:
        """Convert to dictionary."""
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict) -> "EncryptedBlob":
        """Create from dictionary."""
        return cls(**data)

    def to_json(self) -> str:
        """Serialize to JSON string."""
        return json.dumps(self.to_dict())

    @classmethod
    def from_json(cls, json_str: str) -> "EncryptedBlob":
        """Deserialize from JSON string."""
        return cls.from_dict(json.loads(json_str))


@dataclass
class UserCredentials:
    """User authentication data stored on the server."""

    username: str
    # Hashed password for server-side auth (separate from master password)
    password_hash: str
    # Salt used for server-side password hashing
    auth_salt: str
    created_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())

    def to_dict(self) -> dict:
        """Convert to dictionary."""
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict) -> "UserCredentials":
        """Create from dictionary."""
        return cls(**data)
