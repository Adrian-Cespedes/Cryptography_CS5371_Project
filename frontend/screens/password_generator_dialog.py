"""Password generator dialog."""

from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QDialog,
    QVBoxLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPushButton,
    QCheckBox,
    QSlider,
    QSpinBox,
    QFrame,
    QProgressBar,
)
from PySide6.QtGui import QGuiApplication

from ..styles import COLORS
from shared.password_generator import PasswordGenerator, PasswordOptions


class PasswordGeneratorDialog(QDialog):
    """Dialog for generating secure passwords."""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.generator = PasswordGenerator()
        self._password = ""
        self._setup_ui()
        self._generate()
    
    def _setup_ui(self):
        self.setWindowTitle("Password Generator")
        self.setMinimumWidth(450)
        self.setStyleSheet(f"""
            QDialog {{
                background-color: {COLORS['bg_dark']};
            }}
        """)
        
        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 24, 24, 24)
        layout.setSpacing(20)
        
        # Title
        title = QLabel("🎲 Generate Password")
        title.setStyleSheet(f"font-size: 20px; font-weight: 600; color: {COLORS['text_primary']};")
        layout.addWidget(title)
        
        # Generated password display
        password_frame = QFrame()
        password_frame.setStyleSheet(f"""
            QFrame {{
                background-color: {COLORS['bg_card']};
                border-radius: 8px;
                border: 1px solid {COLORS['border']};
            }}
        """)
        password_layout = QHBoxLayout(password_frame)
        password_layout.setContentsMargins(16, 12, 16, 12)
        
        self.password_display = QLineEdit()
        self.password_display.setReadOnly(True)
        self.password_display.setStyleSheet(f"""
            QLineEdit {{
                background: transparent;
                border: none;
                font-family: 'Consolas', 'Monaco', monospace;
                font-size: 16px;
                color: {COLORS['text_primary']};
            }}
        """)
        password_layout.addWidget(self.password_display)
        
        copy_btn = QPushButton("📋")
        copy_btn.setObjectName("icon_button")
        copy_btn.setFixedSize(36, 36)
        copy_btn.setToolTip("Copy to clipboard")
        copy_btn.clicked.connect(self._copy_password)
        password_layout.addWidget(copy_btn)
        
        refresh_btn = QPushButton("🔄")
        refresh_btn.setObjectName("icon_button")
        refresh_btn.setFixedSize(36, 36)
        refresh_btn.setToolTip("Generate new")
        refresh_btn.clicked.connect(self._generate)
        password_layout.addWidget(refresh_btn)
        
        layout.addWidget(password_frame)
        
        # Strength indicator
        strength_layout = QHBoxLayout()
        strength_label = QLabel("Strength:")
        strength_label.setStyleSheet(f"color: {COLORS['text_secondary']};")
        strength_layout.addWidget(strength_label)
        
        self.strength_bar = QProgressBar()
        self.strength_bar.setMinimum(0)
        self.strength_bar.setMaximum(100)
        self.strength_bar.setFixedHeight(8)
        self.strength_bar.setTextVisible(False)
        strength_layout.addWidget(self.strength_bar)
        
        self.strength_text = QLabel("Strong")
        self.strength_text.setStyleSheet(f"color: {COLORS['success']}; font-weight: 500;")
        strength_layout.addWidget(self.strength_text)
        
        layout.addLayout(strength_layout)
        
        # Options
        options_frame = QFrame()
        options_frame.setStyleSheet(f"""
            QFrame {{
                background-color: {COLORS['bg_card']};
                border-radius: 8px;
                border: 1px solid {COLORS['border']};
            }}
        """)
        options_layout = QVBoxLayout(options_frame)
        options_layout.setContentsMargins(16, 16, 16, 16)
        options_layout.setSpacing(12)
        
        # Length slider
        length_layout = QHBoxLayout()
        length_label = QLabel("Length:")
        length_label.setStyleSheet(f"color: {COLORS['text_secondary']};")
        length_layout.addWidget(length_label)
        
        self.length_slider = QSlider(Qt.Orientation.Horizontal)
        self.length_slider.setMinimum(8)
        self.length_slider.setMaximum(64)
        self.length_slider.setValue(16)
        self.length_slider.valueChanged.connect(self._on_option_changed)
        length_layout.addWidget(self.length_slider)
        
        self.length_spin = QSpinBox()
        self.length_spin.setMinimum(8)
        self.length_spin.setMaximum(64)
        self.length_spin.setValue(16)
        self.length_spin.setFixedWidth(60)
        self.length_spin.valueChanged.connect(self._on_spin_changed)
        length_layout.addWidget(self.length_spin)
        
        options_layout.addLayout(length_layout)
        
        # Character options
        self.lowercase_cb = QCheckBox("Lowercase (a-z)")
        self.lowercase_cb.setChecked(True)
        self.lowercase_cb.stateChanged.connect(self._on_option_changed)
        options_layout.addWidget(self.lowercase_cb)
        
        self.uppercase_cb = QCheckBox("Uppercase (A-Z)")
        self.uppercase_cb.setChecked(True)
        self.uppercase_cb.stateChanged.connect(self._on_option_changed)
        options_layout.addWidget(self.uppercase_cb)
        
        self.numbers_cb = QCheckBox("Numbers (0-9)")
        self.numbers_cb.setChecked(True)
        self.numbers_cb.stateChanged.connect(self._on_option_changed)
        options_layout.addWidget(self.numbers_cb)
        
        self.symbols_cb = QCheckBox("Symbols (!@#$%...)")
        self.symbols_cb.setChecked(True)
        self.symbols_cb.stateChanged.connect(self._on_option_changed)
        options_layout.addWidget(self.symbols_cb)
        
        self.ambiguous_cb = QCheckBox("Exclude ambiguous (0, O, l, 1, I)")
        self.ambiguous_cb.setChecked(True)
        self.ambiguous_cb.stateChanged.connect(self._on_option_changed)
        options_layout.addWidget(self.ambiguous_cb)
        
        layout.addWidget(options_frame)
        
        # Buttons
        buttons = QHBoxLayout()
        buttons.addStretch()
        
        cancel_btn = QPushButton("Cancel")
        cancel_btn.setObjectName("secondary")
        cancel_btn.clicked.connect(self.reject)
        buttons.addWidget(cancel_btn)
        
        use_btn = QPushButton("Use Password")
        use_btn.clicked.connect(self.accept)
        buttons.addWidget(use_btn)
        
        layout.addLayout(buttons)
    
    def _get_options(self) -> PasswordOptions:
        """Get current password options."""
        return PasswordOptions(
            length=self.length_slider.value(),
            include_lowercase=self.lowercase_cb.isChecked(),
            include_uppercase=self.uppercase_cb.isChecked(),
            include_numbers=self.numbers_cb.isChecked(),
            include_symbols=self.symbols_cb.isChecked(),
            exclude_ambiguous=self.ambiguous_cb.isChecked(),
        )
    
    def _generate(self):
        """Generate a new password."""
        options = self._get_options()
        
        # Ensure at least one option is selected
        if not any([
            options.include_lowercase,
            options.include_uppercase,
            options.include_numbers,
            options.include_symbols,
        ]):
            self.lowercase_cb.setChecked(True)
            options = self._get_options()
        
        self._password = self.generator.generate(options)
        self.password_display.setText(self._password)
        
        # Update strength indicator
        entropy = self.generator.estimate_entropy(options)
        strength_label = self.generator.get_strength_label(entropy)
        strength_color = self.generator.get_strength_color(entropy)
        
        # Map entropy to 0-100 scale
        strength_value = min(100, int(entropy))
        self.strength_bar.setValue(strength_value)
        self.strength_bar.setStyleSheet(f"""
            QProgressBar {{
                background-color: {COLORS['bg_input']};
                border: none;
                border-radius: 4px;
            }}
            QProgressBar::chunk {{
                background-color: {strength_color};
                border-radius: 4px;
            }}
        """)
        self.strength_text.setText(strength_label)
        self.strength_text.setStyleSheet(f"color: {strength_color}; font-weight: 500;")
    
    def _on_option_changed(self):
        """Handle option change."""
        self.length_spin.setValue(self.length_slider.value())
        self._generate()
    
    def _on_spin_changed(self):
        """Handle spin box change."""
        self.length_slider.setValue(self.length_spin.value())
    
    def _copy_password(self):
        """Copy password to clipboard."""
        clipboard = QGuiApplication.clipboard()
        clipboard.setText(self._password)
    
    def get_password(self) -> str:
        """Get the generated password."""
        return self._password
