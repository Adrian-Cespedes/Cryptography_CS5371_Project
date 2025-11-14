"""Main dashboard screen for the password manager."""

from __future__ import annotations

from typing import Dict

from textual import on
from textual.app import ComposeResult
from textual.containers import Container, Vertical
from textual.screen import Screen
from textual.widgets import Input, Static

from ..data.models import VaultItem
from ..data.providers import VaultProvider
from ..widgets.header import AppHeader
from ..widgets.item_detail import ItemDetail
from ..widgets.item_list import ItemList, ItemSelected


class DashboardScreen(Screen):
    """Single screen layout for password manager."""

    CSS_PATH = "../themes/dashboard.tcss"

    BINDINGS = [
        ("ctrl+n", "new_item", "Nuevo item"),
        ("ctrl+f", "focus_search", "Buscar"),
        ("ctrl+r", "refresh_data", "Actualizar"),
    ]

    def __init__(self, provider: VaultProvider) -> None:
        super().__init__()
        self._provider = provider
        self._items: Dict[str, VaultItem] = {}

    def compose(self) -> ComposeResult:
        yield AppHeader()
        with Container(id="main-layout"):
            with Container(id="center-pane"):
                with Vertical(id="search-pane"):
                    yield Static("Gestor de Contraseñas", classes="section-title")
                    self.search_input = Input(placeholder="Buscar por nombre o usuario", id="search-input")
                    yield self.search_input
                self.item_list = ItemList()
                yield self.item_list
            self.item_detail = ItemDetail()
            yield self.item_detail
        self.status_bar = Static("Listo", id="status-bar")
        yield self.status_bar

    def on_mount(self) -> None:
        self._load_data()
        # Set default detail text
        self.item_detail.clear()

    def _load_data(self) -> None:
        items = self._provider.get_all_items()
        self._items = {item.identifier: item for item in items}
        self.item_list.set_items(items)
        self.status_bar.update(f"Mostrando {len(items)} items")

    @on(ItemSelected)
    def handle_item_selected(self, event: ItemSelected) -> None:
        item = self._items.get(event.item_id)
        if item:
            self.item_detail.update_item(item)
            self.status_bar.update(f"Item seleccionado: {item.title}")
        else:
            self.item_detail.clear()
            self.status_bar.update("Item no encontrado")

    @on(Input.Changed, "#search-input")
    def handle_search_changed(self, event: Input.Changed) -> None:
        value = event.value.strip()
        if not value:
            self._show_all_items()
            return
        results = self._provider.search_items(value)
        self.item_list.set_items(results)
        self.status_bar.update(f"{len(results)} resultado(s) para '{value}'")
        self.item_detail.clear()

    def _show_all_items(self) -> None:
        items = self._provider.get_all_items()
        self.item_list.set_items(items)
        self.status_bar.update(f"Mostrando {len(items)} items")

    def action_focus_search(self) -> None:
        self.set_focus(self.search_input)

    def action_new_item(self) -> None:
        self.status_bar.update("Acción de crear item pendiente de backend…")

    def action_refresh_data(self) -> None:
        self._load_data()
        self.status_bar.update("Datos recargados")
