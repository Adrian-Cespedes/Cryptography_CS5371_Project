"""Shared header widget for the password manager UI."""

from __future__ import annotations

from datetime import datetime

from textual.widgets import Static


class AppHeader(Static):
    """Top header showing branding and current timestamp."""

    def on_mount(self) -> None:
        self.set_interval(60, self.refresh_timestamp)
        self.refresh_timestamp()

    def refresh_timestamp(self) -> None:
        timestamp = datetime.now().strftime("%d %b %Y · %H:%M")
        self.update(f"🔐 Proton Vault · {timestamp}")
