"""Main dashboard screen for the password manager."""

from __future__ import annotations

from typing import Optional, List

from PySide6.QtCore import Qt, Signal, Slot, QTimer
from PySide6.QtWidgets import (
    QWidget,
    QVBoxLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPushButton,
    QFrame,
    QScrollArea,
    QSplitter,
    QMessageBox,
    QFileDialog,
    QTextEdit,
    QCheckBox,
    QSlider,
    QSpinBox,
)
from PySide6.QtGui import QClipboard, QGuiApplication

from ..styles import COLORS
from shared.models import VaultItem
from shared.password_generator import PasswordGenerator, PasswordOptions


class ItemWidget(QFrame):
    """Widget representing a single vault item in the list."""
    
    clicked = Signal(str)  # item_id
    
    def __init__(self, item: VaultItem, parent=None):
        super().__init__(parent)
        self.item = item
        self._setup_ui()
    
    def _setup_ui(self):
        self.setStyleSheet(f"""
            QFrame {{
                background-color: {COLORS['bg_card']};
                border-radius: 8px;
                border: 1px solid {COLORS['border']};
                padding: 12px;
            }}
            QFrame:hover {{
                background-color: {COLORS['item_hover']};
                border-color: {COLORS['primary']};
            }}
        """)
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        
        layout = QVBoxLayout(self)
        layout.setContentsMargins(12, 12, 12, 12)
        layout.setSpacing(4)
        
        # Title row
        title_row = QHBoxLayout()
        
        # Icon placeholder (first letter)
        icon = QLabel(self.item.title[0].upper() if self.item.title else "?")
        icon.setFixedSize(40, 40)
        icon.setAlignment(Qt.AlignmentFlag.AlignCenter)
        icon.setStyleSheet(f"""
            background-color: {COLORS['primary']};
            color: white;
            border-radius: 8px;
            font-size: 16px;
            font-weight: 600;
        """)
        title_row.addWidget(icon)
        
        # Title and username
        info_layout = QVBoxLayout()
        info_layout.setSpacing(2)
        
        title = QLabel(self.item.title)
        title.setStyleSheet(f"font-weight: 600; color: {COLORS['text_primary']}; background: transparent;")
        info_layout.addWidget(title)
        
        username = QLabel(self.item.username)
        username.setStyleSheet(f"color: {COLORS['text_secondary']}; font-size: 12px; background: transparent;")
        info_layout.addWidget(username)
        
        title_row.addLayout(info_layout)
        title_row.addStretch()
        
        layout.addLayout(title_row)
    
    def mousePressEvent(self, event):
        self.clicked.emit(self.item.id)
        super().mousePressEvent(event)
    
    def set_selected(self, selected: bool):
        """Set the selected state."""
        if selected:
            self.setStyleSheet(f"""
                QFrame {{
                    background-color: {COLORS['item_selected']};
                    border-radius: 8px;
                    border: 1px solid {COLORS['primary']};
                    padding: 12px;
                }}
            """)
        else:
            self.setStyleSheet(f"""
                QFrame {{
                    background-color: {COLORS['bg_card']};
                    border-radius: 8px;
                    border: 1px solid {COLORS['border']};
                    padding: 12px;
                }}
                QFrame:hover {{
                    background-color: {COLORS['item_hover']};
                    border-color: {COLORS['primary']};
                }}
            """)


class ItemListPanel(QWidget):
    """Panel showing the list of vault items."""
    
    item_selected = Signal(str)  # item_id
    add_clicked = Signal()
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self._items: List[VaultItem] = []
        self._item_widgets: dict[str, ItemWidget] = {}
        self._selected_id: Optional[str] = None
        self._setup_ui()
    
    def _setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(12)
        
        # Header
        header = QHBoxLayout()
        title = QLabel("Items")
        title.setObjectName("section_title")
        header.addWidget(title)
        header.addStretch()
        
        add_btn = QPushButton("+ Add")
        add_btn.clicked.connect(self.add_clicked.emit)
        header.addWidget(add_btn)
        
        layout.addLayout(header)
        
        # Search
        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("🔍 Search items...")
        self.search_input.setMinimumHeight(40)
        self.search_input.textChanged.connect(self._filter_items)
        layout.addWidget(self.search_input)
        
        # Scroll area for items
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        scroll.setStyleSheet("QScrollArea { border: none; background: transparent; }")
        
        self.list_container = QWidget()
        self.list_layout = QVBoxLayout(self.list_container)
        self.list_layout.setContentsMargins(0, 0, 0, 0)
        self.list_layout.setSpacing(8)
        self.list_layout.addStretch()
        
        scroll.setWidget(self.list_container)
        layout.addWidget(scroll)
    
    def set_items(self, items: List[VaultItem]):
        """Set the list of items to display."""
        self._items = items
        self._rebuild_list()
    
    def _rebuild_list(self):
        """Rebuild the item list."""
        # Clear existing widgets
        for widget in self._item_widgets.values():
            widget.deleteLater()
        self._item_widgets.clear()
        
        # Remove stretch
        while self.list_layout.count() > 0:
            item = self.list_layout.takeAt(0)
            if item.widget():
                item.widget().deleteLater()
        
        # Add items
        search_text = self.search_input.text().lower()
        for item in self._items:
            # Filter by search
            if search_text:
                if (search_text not in item.title.lower() and 
                    search_text not in item.username.lower() and
                    search_text not in item.url.lower()):
                    continue
            
            widget = ItemWidget(item)
            widget.clicked.connect(self._on_item_clicked)
            self._item_widgets[item.id] = widget
            self.list_layout.addWidget(widget)
        
        # Add stretch at end
        self.list_layout.addStretch()
        
        # Restore selection
        if self._selected_id and self._selected_id in self._item_widgets:
            self._item_widgets[self._selected_id].set_selected(True)
    
    def _filter_items(self):
        """Filter items based on search text."""
        self._rebuild_list()
    
    def _on_item_clicked(self, item_id: str):
        """Handle item click."""
        # Deselect previous
        if self._selected_id and self._selected_id in self._item_widgets:
            self._item_widgets[self._selected_id].set_selected(False)
        
        # Select new
        self._selected_id = item_id
        if item_id in self._item_widgets:
            self._item_widgets[item_id].set_selected(True)
        
        self.item_selected.emit(item_id)
    
    def select_item(self, item_id: str):
        """Programmatically select an item."""
        self._on_item_clicked(item_id)


class ItemDetailPanel(QWidget):
    """Panel showing details of a selected item with editing capabilities."""
    
    item_saved = Signal(dict, bool)  # item_data, is_new
    item_deleted = Signal(str)  # item_id
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self._current_item: Optional[VaultItem] = None
        self._is_editing = False
        self._is_new = False
        self._password_visible = False
        self._setup_ui()
    
    def _setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(16)
        
        # Title
        self.title_label = QLabel("Item Details")
        self.title_label.setObjectName("section_title")
        layout.addWidget(self.title_label)
        
        # Form container
        form = QFrame()
        form.setStyleSheet(f"QFrame {{ background: {COLORS['bg_card']}; border-radius: 12px; }}")
        form_layout = QVBoxLayout(form)
        form_layout.setContentsMargins(20, 20, 20, 20)
        form_layout.setSpacing(16)
        
        # Title field
        form_layout.addWidget(QLabel("Title"))
        self.title_input = QLineEdit()
        self.title_input.setPlaceholderText("e.g., Netflix, GitHub...")
        self.title_input.setMinimumHeight(40)
        form_layout.addWidget(self.title_input)
        
        # Username field
        form_layout.addWidget(QLabel("Username / Email"))
        self.username_input = QLineEdit()
        self.username_input.setPlaceholderText("username@example.com")
        self.username_input.setMinimumHeight(40)
        form_layout.addWidget(self.username_input)
        
        # Password field
        form_layout.addWidget(QLabel("Password"))
        password_row = QHBoxLayout()
        self.password_input = QLineEdit()
        self.password_input.setPlaceholderText("••••••••")
        self.password_input.setEchoMode(QLineEdit.EchoMode.Password)
        self.password_input.setMinimumHeight(40)
        password_row.addWidget(self.password_input)
        
        self.show_pass_btn = QPushButton("👁")
        self.show_pass_btn.setObjectName("icon_button")
        self.show_pass_btn.setFixedSize(40, 40)
        self.show_pass_btn.clicked.connect(self._toggle_password_visibility)
        password_row.addWidget(self.show_pass_btn)
        
        self.copy_pass_btn = QPushButton("📋")
        self.copy_pass_btn.setObjectName("icon_button")
        self.copy_pass_btn.setFixedSize(40, 40)
        self.copy_pass_btn.setToolTip("Copy password")
        self.copy_pass_btn.clicked.connect(self._copy_password)
        password_row.addWidget(self.copy_pass_btn)
        
        self.gen_pass_btn = QPushButton("🎲")
        self.gen_pass_btn.setObjectName("icon_button")
        self.gen_pass_btn.setFixedSize(40, 40)
        self.gen_pass_btn.setToolTip("Generate password")
        self.gen_pass_btn.clicked.connect(self._show_password_generator)
        password_row.addWidget(self.gen_pass_btn)
        
        form_layout.addLayout(password_row)
        
        # URL field
        form_layout.addWidget(QLabel("URL"))
        self.url_input = QLineEdit()
        self.url_input.setPlaceholderText("https://example.com")
        self.url_input.setMinimumHeight(40)
        form_layout.addWidget(self.url_input)
        
        # Notes field
        form_layout.addWidget(QLabel("Notes"))
        self.notes_input = QTextEdit()
        self.notes_input.setPlaceholderText("Additional notes...")
        self.notes_input.setMinimumHeight(80)
        self.notes_input.setMaximumHeight(120)
        form_layout.addWidget(self.notes_input)
        
        layout.addWidget(form)
        
        # Action buttons
        actions = QHBoxLayout()
        
        self.save_btn = QPushButton("💾 Save")
        self.save_btn.clicked.connect(self._save_item)
        actions.addWidget(self.save_btn)
        
        self.cancel_btn = QPushButton("Cancel")
        self.cancel_btn.setObjectName("secondary")
        self.cancel_btn.clicked.connect(self._cancel_edit)
        actions.addWidget(self.cancel_btn)
        
        self.edit_btn = QPushButton("✏️ Edit")
        self.edit_btn.clicked.connect(self._start_editing)
        actions.addWidget(self.edit_btn)
        
        self.delete_btn = QPushButton("🗑 Delete")
        self.delete_btn.setObjectName("danger")
        self.delete_btn.clicked.connect(self._delete_item)
        actions.addWidget(self.delete_btn)
        
        actions.addStretch()
        layout.addLayout(actions)
        
        layout.addStretch()
        
        # Initial state
        self._update_state()
    
    def _update_state(self):
        """Update UI state based on current mode."""
        editing = self._is_editing or self._is_new
        
        # Enable/disable inputs
        self.title_input.setReadOnly(not editing)
        self.username_input.setReadOnly(not editing)
        self.password_input.setReadOnly(not editing)
        self.url_input.setReadOnly(not editing)
        self.notes_input.setReadOnly(not editing)
        
        # Show/hide buttons
        self.save_btn.setVisible(editing)
        self.cancel_btn.setVisible(editing)
        self.edit_btn.setVisible(not editing and self._current_item is not None)
        self.delete_btn.setVisible(not self._is_new and self._current_item is not None)
        self.gen_pass_btn.setEnabled(editing)
    
    def show_item(self, item: Optional[VaultItem]):
        """Display an item."""
        self._current_item = item
        self._is_editing = False
        self._is_new = False
        
        if item:
            self.title_label.setText(item.title)
            self.title_input.setText(item.title)
            self.username_input.setText(item.username)
            self.password_input.setText(item.password)
            self.url_input.setText(item.url)
            self.notes_input.setText(item.notes)
        else:
            self._clear_form()
        
        self._update_state()
    
    def start_new_item(self):
        """Start creating a new item."""
        self._current_item = None
        self._is_editing = False
        self._is_new = True
        self._clear_form()
        self.title_label.setText("New Item")
        self._update_state()
        self.title_input.setFocus()
    
    def _clear_form(self):
        """Clear all form fields."""
        self.title_label.setText("Item Details")
        self.title_input.clear()
        self.username_input.clear()
        self.password_input.clear()
        self.url_input.clear()
        self.notes_input.clear()
    
    def _start_editing(self):
        """Start editing mode."""
        self._is_editing = True
        self._update_state()
        self.title_input.setFocus()
    
    def _cancel_edit(self):
        """Cancel editing."""
        if self._is_new:
            self._clear_form()
            self._is_new = False
        else:
            self.show_item(self._current_item)
        self._is_editing = False
        self._update_state()
    
    def _save_item(self):
        """Save the current item."""
        title = self.title_input.text().strip()
        username = self.username_input.text().strip()
        password = self.password_input.text()
        url = self.url_input.text().strip()
        notes = self.notes_input.toPlainText().strip()
        
        if not title:
            QMessageBox.warning(self, "Validation Error", "Title is required")
            return
        if not username:
            QMessageBox.warning(self, "Validation Error", "Username is required")
            return
        if not password:
            QMessageBox.warning(self, "Validation Error", "Password is required")
            return
        
        item_data = {
            "title": title,
            "username": username,
            "password": password,
            "url": url,
            "notes": notes,
        }
        
        if not self._is_new and self._current_item:
            item_data["id"] = self._current_item.id
        
        self.item_saved.emit(item_data, self._is_new)
        self._is_editing = False
        self._is_new = False
        self._update_state()
    
    def _delete_item(self):
        """Delete the current item."""
        if not self._current_item:
            return
        
        reply = QMessageBox.question(
            self,
            "Confirm Delete",
            f"Are you sure you want to delete '{self._current_item.title}'?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
        )
        
        if reply == QMessageBox.StandardButton.Yes:
            self.item_deleted.emit(self._current_item.id)
            self._clear_form()
            self._current_item = None
            self._update_state()
    
    def _toggle_password_visibility(self):
        """Toggle password visibility."""
        self._password_visible = not self._password_visible
        if self._password_visible:
            self.password_input.setEchoMode(QLineEdit.EchoMode.Normal)
            self.show_pass_btn.setText("🙈")
        else:
            self.password_input.setEchoMode(QLineEdit.EchoMode.Password)
            self.show_pass_btn.setText("👁")
    
    def _copy_password(self):
        """Copy password to clipboard."""
        password = self.password_input.text()
        if password:
            clipboard = QGuiApplication.clipboard()
            clipboard.setText(password)
            
            # Show temporary feedback
            self.copy_pass_btn.setText("✓")
            QTimer.singleShot(1500, lambda: self.copy_pass_btn.setText("📋"))
    
    def _show_password_generator(self):
        """Show password generator dialog."""
        from .password_generator_dialog import PasswordGeneratorDialog
        
        dialog = PasswordGeneratorDialog(self)
        if dialog.exec():
            password = dialog.get_password()
            self.password_input.setText(password)


class DashboardScreen(QWidget):
    """Main dashboard screen showing the vault."""
    
    logout_requested = Signal()
    
    def __init__(self, session_manager, parent=None):
        super().__init__(parent)
        self.session = session_manager
        self._setup_ui()
        self._load_items()
    
    def _setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)
        
        # Header
        header = QFrame()
        header.setObjectName("header")
        header.setFixedHeight(60)
        header_layout = QHBoxLayout(header)
        header_layout.setContentsMargins(20, 0, 20, 0)
        
        logo = QLabel("🔐 Proton Vault")
        logo.setStyleSheet(f"font-size: 20px; font-weight: 600; color: {COLORS['primary']}; background: transparent;")
        header_layout.addWidget(logo)
        
        header_layout.addStretch()
        
        # Status indicator
        self.status_label = QLabel("● Online")
        self.status_label.setStyleSheet(f"color: {COLORS['success']}; background: transparent;")
        header_layout.addWidget(self.status_label)
        
        # User info
        username = self.session.state.username or "User"
        user_label = QLabel(f"👤 {username}")
        user_label.setStyleSheet(f"color: {COLORS['text_secondary']}; background: transparent;")
        header_layout.addWidget(user_label)
        
        # Sync button
        sync_btn = QPushButton("🔄 Sync")
        sync_btn.setObjectName("secondary")
        sync_btn.clicked.connect(self._sync_vault)
        header_layout.addWidget(sync_btn)
        
        # Export button
        export_btn = QPushButton("📤 Export")
        export_btn.setObjectName("secondary")
        export_btn.clicked.connect(self._export_backup)
        header_layout.addWidget(export_btn)
        
        # Logout button
        logout_btn = QPushButton("Logout")
        logout_btn.setObjectName("secondary")
        logout_btn.clicked.connect(self._logout)
        header_layout.addWidget(logout_btn)
        
        layout.addWidget(header)
        
        # Main content
        content = QSplitter(Qt.Orientation.Horizontal)
        content.setStyleSheet(f"QSplitter::handle {{ background: {COLORS['border']}; width: 1px; }}")
        
        # Left panel - Item list
        left_panel = QWidget()
        left_panel.setMinimumWidth(300)
        left_panel.setMaximumWidth(400)
        left_layout = QVBoxLayout(left_panel)
        left_layout.setContentsMargins(16, 16, 16, 16)
        
        self.item_list = ItemListPanel()
        self.item_list.item_selected.connect(self._on_item_selected)
        self.item_list.add_clicked.connect(self._on_add_clicked)
        left_layout.addWidget(self.item_list)
        
        content.addWidget(left_panel)
        
        # Right panel - Item details
        right_panel = QWidget()
        right_layout = QVBoxLayout(right_panel)
        right_layout.setContentsMargins(0, 0, 0, 0)
        
        self.item_detail = ItemDetailPanel()
        self.item_detail.item_saved.connect(self._on_item_saved)
        self.item_detail.item_deleted.connect(self._on_item_deleted)
        right_layout.addWidget(self.item_detail)
        
        content.addWidget(right_panel)
        content.setSizes([350, 650])
        
        layout.addWidget(content)
        
        # Update status based on session
        self._update_status()
    
    def _update_status(self):
        """Update the status indicator."""
        if self.session.state.is_offline:
            self.status_label.setText("● Offline")
            self.status_label.setStyleSheet(f"color: {COLORS['warning']}; background: transparent;")
        else:
            self.status_label.setText("● Online")
            self.status_label.setStyleSheet(f"color: {COLORS['success']}; background: transparent;")
    
    def _load_items(self):
        """Load items from session."""
        items = self.session.get_all_items()
        self.item_list.set_items(items)
    
    def _on_item_selected(self, item_id: str):
        """Handle item selection."""
        item = self.session.get_item(item_id)
        self.item_detail.show_item(item)
    
    def _on_add_clicked(self):
        """Handle add button click."""
        self.item_detail.start_new_item()
    
    def _on_item_saved(self, item_data: dict, is_new: bool):
        """Handle item save."""
        if is_new:
            item_id = self.session.add_item(
                title=item_data["title"],
                username=item_data["username"],
                password=item_data["password"],
                url=item_data.get("url", ""),
                notes=item_data.get("notes", ""),
            )
        else:
            self.session.update_item(
                item_data["id"],
                title=item_data["title"],
                username=item_data["username"],
                password=item_data["password"],
                url=item_data.get("url", ""),
                notes=item_data.get("notes", ""),
            )
        
        self._load_items()
        self._update_status()
    
    def _on_item_deleted(self, item_id: str):
        """Handle item deletion."""
        self.session.delete_item(item_id)
        self._load_items()
        self._update_status()
    
    def _sync_vault(self):
        """Sync vault with server."""
        success = self.session.sync_vault()
        self._update_status()
        
        if success:
            QMessageBox.information(self, "Sync", "Vault synced successfully!")
        else:
            QMessageBox.warning(self, "Sync", "Failed to sync. Working in offline mode.")
    
    def _export_backup(self):
        """Export vault backup."""
        file_path, _ = QFileDialog.getSaveFileName(
            self,
            "Export Vault Backup",
            f"vault_{self.session.state.username}_backup.backup",
            "Backup Files (*.backup);;All Files (*)",
        )
        
        if file_path:
            try:
                self.session.export_backup(file_path)
                QMessageBox.information(self, "Export", f"Backup saved to:\n{file_path}")
            except Exception as e:
                QMessageBox.critical(self, "Export Error", f"Failed to export: {e}")
    
    def _logout(self):
        """Handle logout."""
        reply = QMessageBox.question(
            self,
            "Logout",
            "Are you sure you want to logout?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
        )
        
        if reply == QMessageBox.StandardButton.Yes:
            self.session.logout()
            self.logout_requested.emit()
