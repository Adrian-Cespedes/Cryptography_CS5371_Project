"""Widget showing user vaults."""

from __future__ import annotations

from dataclasses import dataclass

from textual import events
from textual.message import Message
from textual.reactive import reactive
from textual.widgets import Label, ListItem, ListView

from ..data.models import Vault


@dataclass
class VaultSummary:
    identifier: str
    name: str
    color: str
    count: int


class VaultSelected(Message):
    """Message emitted when a vault is selected from the list."""

    def __init__(self, vault_id: str) -> None:
        self.vault_id = vault_id
        super().__init__()


class VaultList(ListView):
    """Selectors for vaults."""

    focused_vault: reactive[str | None] = reactive(None)

    def __init__(self) -> None:
        super().__init__()
        self._vault_lookup: dict[str, VaultSummary] = {}

    def set_vaults(self, vaults: list[Vault]) -> None:
        self._vault_lookup = {
            vault.identifier: VaultSummary(
                identifier=vault.identifier,
                name=vault.name,
                color=vault.color,
                count=len(vault.items),
            )
            for vault in vaults
        }
        self._populate_items()

    def _populate_items(self) -> None:
        self.clear()
        for summary in self._vault_lookup.values():
            pill = Label(str(summary.count), classes="count-pill")
            # Use the recommended way to set styles in Textual 6.5.0
            pill.styles.background = summary.color
            pill.styles.color = "#0f0f17"
            pill.styles.padding = (0, 1)

            list_item = ListItem(
                Label(summary.name, classes="vault-name"),
                pill,
                name=summary.identifier,
            )
            self.append(list_item)

        if self.children:
            first_item = self.children[0]
            first_item.focus()
            self.focused_vault = first_item.name

    async def on_list_view_selected(self, event: ListView.Selected) -> None:
        item_name = event.item.name
        self.focused_vault = item_name
        self.post_message(VaultSelected(item_name))

    def on_key(self, event: events.Key) -> None:
        # Provide quick keyboard access to go back to first vault
        if event.key == "home":
            if self.children:
                first_item = self.children[0]
                self.index = 0
                first_item.focus()
                self.focused_vault = first_item.name
                self.post_message(VaultSelected(first_item.name))
                event.stop()
                return
        # Let ListView handle all other keys normally
