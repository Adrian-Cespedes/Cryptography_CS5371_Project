"""Seed phrase dialogs for pepper management."""

from __future__ import annotations

from typing import Optional, List

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QDialog,
    QVBoxLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPushButton,
    QTextEdit,
    QFrame,
    QGridLayout,
    QCheckBox,
    QMessageBox,
)
from PySide6.QtGui import QFont, QGuiApplication

from ..styles import COLORS
from shared.crypto import PepperManager


class SeedPhraseDisplayDialog(QDialog):
    """Dialog to display seed phrase during registration."""
    
    def __init__(self, seed_phrase: List[str], parent=None):
        super().__init__(parent)
        self.seed_phrase = seed_phrase
        self.confirmed = False
        self._setup_ui()
    
    def _setup_ui(self):
        self.setWindowTitle("Save Your Recovery Seed")
        self.setFixedSize(600, 550)
        self.setStyleSheet(f"""
            QDialog {{
                background-color: {COLORS['bg_dark']};
            }}
            QLabel {{
                color: {COLORS['text_primary']};
                background: transparent;
            }}
        """)
        
        layout = QVBoxLayout(self)
        layout.setSpacing(16)
        layout.setContentsMargins(30, 30, 30, 30)
        
        # Warning header
        warning_frame = QFrame()
        warning_frame.setStyleSheet(f"""
            QFrame {{
                background-color: {COLORS['warning']}20;
                border: 1px solid {COLORS['warning']};
                border-radius: 8px;
                padding: 12px;
            }}
        """)
        warning_layout = QVBoxLayout(warning_frame)
        
        warning_title = QLabel("⚠️ IMPORTANT - SAVE THIS RECOVERY SEED")
        warning_title.setStyleSheet(f"""
            font-size: 16px;
            font-weight: 700;
            color: {COLORS['warning']};
        """)
        warning_title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        warning_layout.addWidget(warning_title)
        
        warning_text = QLabel(
            "This is your recovery seed. Write it down and store it in a safe place.\n"
            "If you lose access to this device, you will need this seed to decrypt your passwords.\n"
            "WITHOUT THIS SEED, YOUR PASSWORDS CANNOT BE RECOVERED!"
        )
        warning_text.setStyleSheet(f"color: {COLORS['text_secondary']}; font-size: 13px;")
        warning_text.setWordWrap(True)
        warning_text.setAlignment(Qt.AlignmentFlag.AlignCenter)
        warning_layout.addWidget(warning_text)
        
        layout.addWidget(warning_frame)
        
        # Seed phrase grid
        seed_frame = QFrame()
        seed_frame.setStyleSheet(f"""
            QFrame {{
                background-color: {COLORS['bg_card']};
                border: 1px solid {COLORS['border']};
                border-radius: 12px;
                padding: 16px;
            }}
        """)
        seed_layout = QVBoxLayout(seed_frame)
        
        seed_title = QLabel("Your 32-Word Recovery Seed:")
        seed_title.setStyleSheet(f"font-weight: 600; font-size: 14px; color: {COLORS['text_primary']};")
        seed_layout.addWidget(seed_title)
        
        # Grid of words (8 rows x 4 columns)
        grid = QGridLayout()
        grid.setSpacing(8)
        
        for i, word in enumerate(self.seed_phrase):
            row = i // 4
            col = i % 4
            
            word_frame = QFrame()
            word_frame.setStyleSheet(f"""
                QFrame {{
                    background-color: {COLORS['bg_input']};
                    border: 1px solid {COLORS['border']};
                    border-radius: 6px;
                    padding: 4px;
                }}
            """)
            word_layout = QHBoxLayout(word_frame)
            word_layout.setContentsMargins(8, 4, 8, 4)
            word_layout.setSpacing(6)
            
            num_label = QLabel(f"{i+1}.")
            num_label.setStyleSheet(f"color: {COLORS['text_muted']}; font-size: 11px; min-width: 20px;")
            word_layout.addWidget(num_label)
            
            word_label = QLabel(word)
            word_label.setStyleSheet(f"color: {COLORS['text_primary']}; font-weight: 500; font-size: 13px;")
            word_layout.addWidget(word_label)
            word_layout.addStretch()
            
            grid.addWidget(word_frame, row, col)
        
        seed_layout.addLayout(grid)
        layout.addWidget(seed_frame)
        
        # Copy button
        copy_btn = QPushButton("📋 Copy to Clipboard")
        copy_btn.setStyleSheet(f"""
            QPushButton {{
                background-color: {COLORS['bg_input']};
                color: {COLORS['text_primary']};
                border: 1px solid {COLORS['border']};
                border-radius: 8px;
                padding: 10px 20px;
                font-size: 14px;
            }}
            QPushButton:hover {{
                background-color: {COLORS['item_hover']};
            }}
        """)
        copy_btn.clicked.connect(self._copy_seed)
        layout.addWidget(copy_btn)
        
        # Confirmation checkbox
        self.confirm_check = QCheckBox("I have saved my recovery seed in a secure location")
        self.confirm_check.setStyleSheet(f"""
            QCheckBox {{
                color: {COLORS['text_primary']};
                font-size: 13px;
                spacing: 8px;
            }}
            QCheckBox::indicator {{
                width: 18px;
                height: 18px;
                border: 2px solid {COLORS['border']};
                border-radius: 4px;
                background: {COLORS['bg_input']};
            }}
            QCheckBox::indicator:checked {{
                background: {COLORS['primary']};
                border-color: {COLORS['primary']};
            }}
        """)
        self.confirm_check.stateChanged.connect(self._on_confirm_changed)
        layout.addWidget(self.confirm_check)
        
        # Continue button
        self.continue_btn = QPushButton("Continue")
        self.continue_btn.setEnabled(False)
        self.continue_btn.setStyleSheet(f"""
            QPushButton {{
                background-color: {COLORS['primary']};
                color: white;
                border: none;
                border-radius: 8px;
                padding: 12px 24px;
                font-size: 15px;
                font-weight: 600;
            }}
            QPushButton:hover {{
                background-color: {COLORS['primary_hover']};
            }}
            QPushButton:disabled {{
                background-color: {COLORS['text_muted']};
            }}
        """)
        self.continue_btn.clicked.connect(self._on_continue)
        layout.addWidget(self.continue_btn)
    
    def _copy_seed(self):
        """Copy seed phrase to clipboard."""
        seed_text = " ".join(self.seed_phrase)
        clipboard = QGuiApplication.clipboard()
        clipboard.setText(seed_text)
        
        QMessageBox.information(
            self,
            "Copied",
            "Seed phrase copied to clipboard.\n\n"
            "⚠️ Make sure to store it securely and clear your clipboard!"
        )
    
    def _on_confirm_changed(self, state):
        """Handle confirmation checkbox change."""
        self.continue_btn.setEnabled(state == Qt.CheckState.Checked.value)
    
    def _on_continue(self):
        """Handle continue button click."""
        self.confirmed = True
        self.accept()


class SeedPhraseRecoveryDialog(QDialog):
    """Dialog to recover seed phrase when pepper file is missing."""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.recovered_pepper: Optional[bytes] = None
        self.pepper_manager = PepperManager()
        self._setup_ui()
    
    def _setup_ui(self):
        self.setWindowTitle("Recovery Seed Required")
        self.setFixedSize(550, 450)
        self.setStyleSheet(f"""
            QDialog {{
                background-color: {COLORS['bg_dark']};
            }}
            QLabel {{
                color: {COLORS['text_primary']};
                background: transparent;
            }}
        """)
        
        layout = QVBoxLayout(self)
        layout.setSpacing(16)
        layout.setContentsMargins(30, 30, 30, 30)
        
        # Error header
        error_frame = QFrame()
        error_frame.setStyleSheet(f"""
            QFrame {{
                background-color: {COLORS['error']}20;
                border: 1px solid {COLORS['error']};
                border-radius: 8px;
                padding: 12px;
            }}
        """)
        error_layout = QVBoxLayout(error_frame)
        
        error_title = QLabel("🔑 Recovery Seed Required")
        error_title.setStyleSheet(f"""
            font-size: 18px;
            font-weight: 700;
            color: {COLORS['error']};
        """)
        error_title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        error_layout.addWidget(error_title)
        
        error_text = QLabel(
            "Your pepper file was not found on this device.\n"
            "Please enter your 32-word recovery seed to restore access to your vault."
        )
        error_text.setStyleSheet(f"color: {COLORS['text_secondary']}; font-size: 13px;")
        error_text.setWordWrap(True)
        error_text.setAlignment(Qt.AlignmentFlag.AlignCenter)
        error_layout.addWidget(error_text)
        
        layout.addWidget(error_frame)
        
        # Seed input
        input_label = QLabel("Enter your recovery seed (32 words, space-separated):")
        input_label.setStyleSheet(f"font-weight: 500; font-size: 14px;")
        layout.addWidget(input_label)
        
        self.seed_input = QTextEdit()
        self.seed_input.setPlaceholderText(
            "word1 word2 word3 word4 word5 word6 word7 word8\n"
            "word9 word10 word11 word12 word13 word14 word15 word16\n"
            "word17 word18 word19 word20 word21 word22 word23 word24\n"
            "word25 word26 word27 word28 word29 word30 word31 word32"
        )
        self.seed_input.setStyleSheet(f"""
            QTextEdit {{
                background-color: {COLORS['bg_input']};
                color: {COLORS['text_primary']};
                border: 1px solid {COLORS['border']};
                border-radius: 8px;
                padding: 12px;
                font-size: 13px;
                font-family: monospace;
            }}
            QTextEdit:focus {{
                border-color: {COLORS['primary']};
            }}
        """)
        self.seed_input.setMinimumHeight(120)
        layout.addWidget(self.seed_input)
        
        # Status label
        self.status_label = QLabel("")
        self.status_label.setStyleSheet(f"color: {COLORS['error']}; font-size: 12px;")
        self.status_label.setWordWrap(True)
        layout.addWidget(self.status_label)
        
        # Buttons
        btn_layout = QHBoxLayout()
        
        cancel_btn = QPushButton("Cancel")
        cancel_btn.setStyleSheet(f"""
            QPushButton {{
                background-color: {COLORS['bg_input']};
                color: {COLORS['text_primary']};
                border: 1px solid {COLORS['border']};
                border-radius: 8px;
                padding: 12px 24px;
                font-size: 14px;
            }}
            QPushButton:hover {{
                background-color: {COLORS['item_hover']};
            }}
        """)
        cancel_btn.clicked.connect(self.reject)
        btn_layout.addWidget(cancel_btn)
        
        self.recover_btn = QPushButton("Recover")
        self.recover_btn.setStyleSheet(f"""
            QPushButton {{
                background-color: {COLORS['primary']};
                color: white;
                border: none;
                border-radius: 8px;
                padding: 12px 24px;
                font-size: 14px;
                font-weight: 600;
            }}
            QPushButton:hover {{
                background-color: {COLORS['primary_hover']};
            }}
        """)
        self.recover_btn.clicked.connect(self._on_recover)
        btn_layout.addWidget(self.recover_btn)
        
        layout.addLayout(btn_layout)
    
    def _on_recover(self):
        """Handle recovery button click."""
        seed_text = self.seed_input.toPlainText().strip()
        
        if not seed_text:
            self.status_label.setText("Please enter your recovery seed.")
            return
        
        # Parse seed phrase
        words = seed_text.lower().split()
        
        if len(words) != 32:
            self.status_label.setText(f"Invalid seed phrase: expected 32 words, got {len(words)}.")
            return
        
        try:
            # Convert seed phrase to pepper
            pepper = self.pepper_manager.seed_phrase_to_pepper(words)
            
            # Save the pepper
            self.pepper_manager.save_pepper(pepper)
            
            self.recovered_pepper = pepper
            self.accept()
            
        except ValueError as e:
            self.status_label.setText(str(e))
