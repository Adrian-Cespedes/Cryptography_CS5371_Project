"""Data providers for the password manager TUI.

"""

from __future__ import annotations

from abc import ABC, abstractmethod
from datetime import datetime, timedelta
from typing import List, Protocol

from .models import VaultItem


class VaultProvider(Protocol):
    """Protocol for retrieving items."""

    def get_all_items(self) -> List[VaultItem]:
        ...

    def search_items(self, query: str) -> List[VaultItem]:
        ...


class AbstractVaultProvider(ABC):
    """Base class that concrete providers can inherit from."""

    @abstractmethod
    def get_all_items(self) -> List[VaultItem]:
        raise NotImplementedError

    @abstractmethod
    def search_items(self, query: str) -> List[VaultItem]:
        raise NotImplementedError


class InMemoryVaultProvider(AbstractVaultProvider):
    """Simple provider with hard-coded sample data."""

    def __init__(self) -> None:
        self._items: List[VaultItem] = self._seed()

    @staticmethod
    def _seed() -> List[VaultItem]:
        now = datetime.utcnow()
        recent = now - timedelta(hours=4)
        older = now - timedelta(days=3)

        return [
            VaultItem(
                identifier="itm_netflix",
                title="Netflix",
                username="eric.norbert@proton.me",
                url="https://www.netflix.com",
                notes="Suscripción mensual UHD",
                tags=["streaming"],
                last_modified=recent,
            ),
            VaultItem(
                identifier="itm_spotify",
                title="Spotify",
                username="eric.norbert@proton.me",
                url="https://www.spotify.com",
                notes="Plan familiar",
                tags=["streaming"],
                last_modified=older,
            ),
            VaultItem(
                identifier="itm_github",
                title="GitHub",
                username="eric.dev@proton.me",
                url="https://github.com",
                notes="2FA obligatorio",
                tags=["dev", "2fa"],
                last_modified=now,
            ),
            VaultItem(
                identifier="itm_prod_admin",
                title="Panel Producción",
                username="eric",
                url="https://admin.example.com",
                notes="VPN requerida",
                tags=["infra"],
                last_modified=older,
            ),
            VaultItem(
                identifier="itm_disney",
                title="Disney+",
                username="familia@proton.me",
                url="https://www.disneyplus.com",
                tags=["streaming", "kids"],
                last_modified=recent,
            ),
        ]

    def get_all_items(self) -> List[VaultItem]:
        return list(self._items)

    def search_items(self, query: str) -> List[VaultItem]:
        query_lower = query.lower()
        results: List[VaultItem] = []
        for item in self._items:
            if query_lower in item.title.lower() or query_lower in item.username.lower():
                results.append(item)
        return results
