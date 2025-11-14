"""Data layer primitives for the password manager TUI."""

from .models import Vault, VaultItem
from .providers import InMemoryVaultProvider, VaultProvider

__all__ = ["Vault", "VaultItem", "VaultProvider", "InMemoryVaultProvider"]
