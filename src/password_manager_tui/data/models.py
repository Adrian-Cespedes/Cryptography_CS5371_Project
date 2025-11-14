"""Data models used by the Textual TUI.

These are intentionally lightweight so they can be shared by a future
backend implementation without major changes.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import List


@dataclass(slots=True)
class VaultItem:
    """An individual credential/item stored inside a vault."""

    identifier: str
    title: str
    username: str
    url: str
    notes: str = ""
    tags: List[str] = field(default_factory=list)
    last_modified: datetime = field(default_factory=datetime.utcnow)


@dataclass(slots=True)
class Vault:
    """A logical grouping of credentials."""

    identifier: str
    name: str
    color: str = "#7F5AF0"
    items: List[VaultItem] = field(default_factory=list)
