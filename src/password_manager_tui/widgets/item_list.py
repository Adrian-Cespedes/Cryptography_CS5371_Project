"""Widget listing credentials inside a vault."""

from __future__ import annotations

from dataclasses import dataclass

from textual.message import Message
from textual.reactive import reactive
from textual.widgets import Label, ListItem, ListView

from ..data.models import VaultItem


@dataclass
class ItemSummary:
    identifier: str
    title: str
    username: str
    last_modified_human: str


class ItemSelected(Message):
    """Emitted when a credential is selected."""

    def __init__(self, item_id: str) -> None:
        self.item_id = item_id
        super().__init__()


class ItemList(ListView):
    """Displays credentials for a vault."""

    highlighted_item: reactive[str | None] = reactive(None)

    def __init__(self) -> None:
        super().__init__()
        self._items: dict[str, ItemSummary] = {}

    def set_items(self, entries: list[VaultItem]) -> None:
        self._items = {}
        self.clear()
        for entry in entries:
            summary = ItemSummary(
                identifier=entry.identifier,
                title=entry.title,
                username=entry.username,
                last_modified_human=entry.last_modified.strftime("Actualizado %d %b · %H:%M"),
            )
            self._items[summary.identifier] = summary

            item_widget = ListItem(
                Label(summary.title, classes="item-title"),
                Label(summary.username, classes="item-subtitle"),
                Label(summary.last_modified_human, classes="item-subtitle"),
                name=summary.identifier,
            )
            self.append(item_widget)

        if self.children:
            first = self.children[0]
            first.focus()
            self.highlighted_item = first.name

    async def on_list_view_selected(self, event: ListView.Selected) -> None:
        self.highlighted_item = event.item.name
        self.post_message(ItemSelected(event.item.name))
