"""Details panel for credentials."""

from __future__ import annotations

from textual.widgets import Static

from ..data.models import VaultItem


class ItemDetail(Static):
    """Renders the detail view for a selected credential."""

    def update_item(self, item: VaultItem | None) -> None:
        if item is None:
            self.update("Seleccione un item para ver los detalles.")
            return

        tags = " · ".join(item.tags) if item.tags else "Sin etiquetas"
        body = """
[h2]{title}[/h2]

[b]Usuario:[/b] {username}
[b]URL:[/b] {url}
[b]Notas:[/b]\n{notes}
[b]Etiquetas:[/b] {tags}
[b]Última modificación:[/b] {last_modified}
        """.format(
            title=item.title,
            username=item.username,
            url=item.url or "—",
            notes=item.notes or "Sin notas",
            tags=tags,
            last_modified=item.last_modified.strftime("%d %b %Y · %H:%M"),
        )
        self.update(body)

    def clear(self) -> None:
        self.update("Seleccione un item para ver los detalles.")
