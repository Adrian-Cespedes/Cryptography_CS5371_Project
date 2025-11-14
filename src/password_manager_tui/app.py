"""Textual App for the password manager prototype."""

from __future__ import annotations

import argparse

from textual import on
from textual.app import App

from .data.providers import InMemoryVaultProvider, VaultProvider
from .screens.auth import AuthScreen, AuthCompleted
from .screens.dashboard import DashboardScreen


class PasswordManagerApp(App):
    """Top-level Textual application."""

    TITLE = "Proton Vault"
    SUB_TITLE = "Entrega 1 · TUI"
    CSS_PATH = "themes/dashboard.tcss"

    def __init__(self, provider: VaultProvider | None = None) -> None:
        self._provider = provider or InMemoryVaultProvider()
        super().__init__()

    def on_mount(self) -> None:
        # Show authentication screen first
        auth_screen = AuthScreen()
        self.push_screen(auth_screen)

    @on(AuthCompleted)
    def handle_auth_completed(self, event: AuthCompleted) -> None:
        """Handle authentication completion."""
        if event.success:
            # Authentication successful, show dashboard
            dashboard = DashboardScreen(self._provider)
            self.push_screen(dashboard)
        else:
            # Authentication failed, you could show error or exit
            self.exit()


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Password manager TUI prototype")
    parser.add_argument("--headless", action="store_true", help="Run without rendering (useful for tests)")
    return parser.parse_args()


def main() -> None:
    args = _parse_args()
    app = PasswordManagerApp()
    app.run(headless=args.headless)


if __name__ == "__main__":
    main()
