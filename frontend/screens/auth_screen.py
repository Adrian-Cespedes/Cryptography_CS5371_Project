"""Login/Registration screen for the password manager."""

from __future__ import annotations

from typing import Optional, Callable

from PySide6.QtCore import Qt, Signal, QThread
from PySide6.QtWidgets import (
    QWidget,
    QVBoxLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPushButton,
    QStackedWidget,
    QFrame,
    QFileDialog,
    QMessageBox,
)
from PySide6.QtGui import QPixmap, QFont

from ..styles import COLORS
from .seed_phrase_dialog import SeedPhraseDisplayDialog, SeedPhraseRecoveryDialog
from shared.crypto import PepperManager


class AuthWorker(QThread):
    """Worker thread for authentication operations."""
    
    finished = Signal(bool, str)  # success, message
    
    def __init__(
        self,
        operation: str,
        session_manager,
        username: str,
        auth_password: str,
        master_password: str,
        backup_path: str = "",
    ):
        super().__init__()
        self.operation = operation
        self.session = session_manager
        self.username = username
        self.auth_password = auth_password
        self.master_password = master_password
        self.backup_path = backup_path
    
    def run(self):
        try:
            if self.operation == "login":
                self.session.login(self.username, self.auth_password, self.master_password)
                self.finished.emit(True, "Login successful!")
            elif self.operation == "register":
                self.session.register(self.username, self.auth_password, self.master_password)
                self.finished.emit(True, "Registration successful!")
            elif self.operation == "offline":
                self.session.login_offline(self.username, self.master_password)
                self.finished.emit(True, "Offline login successful!")
            elif self.operation == "backup":
                self.session.login_from_file(self.backup_path, self.master_password)
                self.finished.emit(True, "Loaded from backup!")
        except Exception as e:
            self.finished.emit(False, str(e))


class AuthScreen(QWidget):
    """Login and registration screen."""
    
    login_successful = Signal()
    
    def __init__(self, session_manager):
        super().__init__()
        self.session = session_manager
        self.pepper_manager = PepperManager()
        self._pending_registration = None  # Store registration data during seed phrase flow
        self._setup_ui()
    
    def _setup_ui(self):
        """Setup the UI."""
        layout = QVBoxLayout(self)
        layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.setContentsMargins(40, 40, 40, 40)
        
        # Main container
        container = QFrame()
        container.setFixedWidth(420)
        container.setStyleSheet(f"""
            QFrame {{
                background-color: {COLORS['bg_card']};
                border-radius: 16px;
                border: 1px solid {COLORS['border']};
            }}
        """)
        container_layout = QVBoxLayout(container)
        container_layout.setContentsMargins(40, 40, 40, 40)
        container_layout.setSpacing(20)
        
        # Logo/Title
        title = QLabel("🔐 Proton Vault")
        title.setStyleSheet(f"""
            font-size: 28px;
            font-weight: 700;
            color: {COLORS['primary']};
            background: transparent;
        """)
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        container_layout.addWidget(title)
        
        subtitle = QLabel("Secure Password Manager")
        subtitle.setStyleSheet(f"""
            font-size: 14px;
            color: {COLORS['text_secondary']};
            background: transparent;
            margin-bottom: 20px;
        """)
        subtitle.setAlignment(Qt.AlignmentFlag.AlignCenter)
        container_layout.addWidget(subtitle)
        
        # Stacked widget for login/register
        self.stack = QStackedWidget()
        container_layout.addWidget(self.stack)
        
        # Login page
        login_page = self._create_login_page()
        self.stack.addWidget(login_page)
        
        # Register page
        register_page = self._create_register_page()
        self.stack.addWidget(register_page)
        
        # Offline page
        offline_page = self._create_offline_page()
        self.stack.addWidget(offline_page)
        
        # Status label
        self.status_label = QLabel("")
        self.status_label.setStyleSheet(f"""
            color: {COLORS['error']};
            font-size: 12px;
            background: transparent;
        """)
        self.status_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.status_label.setWordWrap(True)
        container_layout.addWidget(self.status_label)
        
        layout.addWidget(container)
    
    def _create_login_page(self) -> QWidget:
        """Create the login page."""
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setSpacing(16)
        layout.setContentsMargins(0, 0, 0, 0)
        
        # Username
        self.login_username = QLineEdit()
        self.login_username.setPlaceholderText("Username")
        self.login_username.setMinimumHeight(44)
        layout.addWidget(self.login_username)
        
        # Auth Password
        self.login_auth_pass = QLineEdit()
        self.login_auth_pass.setPlaceholderText("Server Password")
        self.login_auth_pass.setEchoMode(QLineEdit.EchoMode.Password)
        self.login_auth_pass.setMinimumHeight(44)
        layout.addWidget(self.login_auth_pass)
        
        # Master Password
        self.login_master_pass = QLineEdit()
        self.login_master_pass.setPlaceholderText("Master Password (for encryption)")
        self.login_master_pass.setEchoMode(QLineEdit.EchoMode.Password)
        self.login_master_pass.setMinimumHeight(44)
        layout.addWidget(self.login_master_pass)
        
        # Login button
        self.login_btn = QPushButton("Login")
        self.login_btn.setMinimumHeight(44)
        self.login_btn.clicked.connect(self._handle_login)
        layout.addWidget(self.login_btn)
        
        # Toggle to register
        toggle_row = QHBoxLayout()
        toggle_label = QLabel("Don't have an account?")
        toggle_label.setStyleSheet(f"color: {COLORS['text_secondary']}; background: transparent;")
        toggle_btn = QPushButton("Register")
        toggle_btn.setObjectName("secondary")
        toggle_btn.clicked.connect(lambda: self.stack.setCurrentIndex(1))
        toggle_row.addWidget(toggle_label)
        toggle_row.addWidget(toggle_btn)
        toggle_row.addStretch()
        layout.addLayout(toggle_row)
        
        # Offline login option
        offline_btn = QPushButton("🔌 Login Offline / Load Backup")
        offline_btn.setObjectName("secondary")
        offline_btn.clicked.connect(lambda: self.stack.setCurrentIndex(2))
        layout.addWidget(offline_btn)
        
        return page
    
    def _create_register_page(self) -> QWidget:
        """Create the registration page."""
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setSpacing(16)
        layout.setContentsMargins(0, 0, 0, 0)
        
        # Username
        self.reg_username = QLineEdit()
        self.reg_username.setPlaceholderText("Username (min 3 characters)")
        self.reg_username.setMinimumHeight(44)
        layout.addWidget(self.reg_username)
        
        # Auth Password
        self.reg_auth_pass = QLineEdit()
        self.reg_auth_pass.setPlaceholderText("Server Password (min 8 characters)")
        self.reg_auth_pass.setEchoMode(QLineEdit.EchoMode.Password)
        self.reg_auth_pass.setMinimumHeight(44)
        layout.addWidget(self.reg_auth_pass)
        
        # Master Password
        self.reg_master_pass = QLineEdit()
        self.reg_master_pass.setPlaceholderText("Master Password (for encryption)")
        self.reg_master_pass.setEchoMode(QLineEdit.EchoMode.Password)
        self.reg_master_pass.setMinimumHeight(44)
        layout.addWidget(self.reg_master_pass)
        
        # Confirm Master Password
        self.reg_master_confirm = QLineEdit()
        self.reg_master_confirm.setPlaceholderText("Confirm Master Password")
        self.reg_master_confirm.setEchoMode(QLineEdit.EchoMode.Password)
        self.reg_master_confirm.setMinimumHeight(44)
        layout.addWidget(self.reg_master_confirm)
        
        # Info label
        info = QLabel("⚠️ Your master password cannot be recovered. Remember it!")
        info.setStyleSheet(f"color: {COLORS['warning']}; font-size: 12px; background: transparent;")
        info.setWordWrap(True)
        layout.addWidget(info)
        
        # Register button
        self.reg_btn = QPushButton("Create Account")
        self.reg_btn.setMinimumHeight(44)
        self.reg_btn.clicked.connect(self._handle_register)
        layout.addWidget(self.reg_btn)
        
        # Toggle to login
        toggle_row = QHBoxLayout()
        toggle_label = QLabel("Already have an account?")
        toggle_label.setStyleSheet(f"color: {COLORS['text_secondary']}; background: transparent;")
        toggle_btn = QPushButton("Login")
        toggle_btn.setObjectName("secondary")
        toggle_btn.clicked.connect(lambda: self.stack.setCurrentIndex(0))
        toggle_row.addWidget(toggle_label)
        toggle_row.addWidget(toggle_btn)
        toggle_row.addStretch()
        layout.addLayout(toggle_row)
        
        return page
    
    def _create_offline_page(self) -> QWidget:
        """Create the offline login page."""
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setSpacing(16)
        layout.setContentsMargins(0, 0, 0, 0)
        
        # Title
        title = QLabel("Offline Mode")
        title.setStyleSheet(f"font-size: 18px; font-weight: 600; color: {COLORS['text_primary']}; background: transparent;")
        layout.addWidget(title)
        
        # Username
        self.offline_username = QLineEdit()
        self.offline_username.setPlaceholderText("Username")
        self.offline_username.setMinimumHeight(44)
        layout.addWidget(self.offline_username)
        
        # Master Password
        self.offline_master_pass = QLineEdit()
        self.offline_master_pass.setPlaceholderText("Master Password")
        self.offline_master_pass.setEchoMode(QLineEdit.EchoMode.Password)
        self.offline_master_pass.setMinimumHeight(44)
        layout.addWidget(self.offline_master_pass)
        
        # Offline login button
        offline_btn = QPushButton("Login from Local Backup")
        offline_btn.setMinimumHeight(44)
        offline_btn.clicked.connect(self._handle_offline_login)
        layout.addWidget(offline_btn)
        
        # Or separator
        sep_layout = QHBoxLayout()
        sep_left = QFrame()
        sep_left.setFrameShape(QFrame.Shape.HLine)
        sep_left.setStyleSheet(f"background: {COLORS['border']};")
        sep_layout.addWidget(sep_left)
        sep_label = QLabel("OR")
        sep_label.setStyleSheet(f"color: {COLORS['text_muted']}; background: transparent; padding: 0 10px;")
        sep_layout.addWidget(sep_label)
        sep_right = QFrame()
        sep_right.setFrameShape(QFrame.Shape.HLine)
        sep_right.setStyleSheet(f"background: {COLORS['border']};")
        sep_layout.addWidget(sep_right)
        layout.addLayout(sep_layout)
        
        # Load from file button
        load_btn = QPushButton("📁 Load Backup File")
        load_btn.setObjectName("secondary")
        load_btn.setMinimumHeight(44)
        load_btn.clicked.connect(self._handle_load_backup)
        layout.addWidget(load_btn)
        
        # Back to login
        back_btn = QPushButton("← Back to Login")
        back_btn.setObjectName("secondary")
        back_btn.clicked.connect(lambda: self.stack.setCurrentIndex(0))
        layout.addWidget(back_btn)
        
        return page
    
    def _show_status(self, message: str, is_error: bool = True):
        """Show a status message."""
        color = COLORS['error'] if is_error else COLORS['success']
        self.status_label.setStyleSheet(f"color: {color}; font-size: 12px; background: transparent;")
        self.status_label.setText(message)
    
    def _clear_status(self):
        """Clear the status message."""
        self.status_label.setText("")
    
    def _check_pepper_or_recover(self) -> bool:
        """Check if pepper exists, or prompt for recovery.
        
        Returns:
            True if pepper is available, False if recovery was cancelled
        """
        if self.pepper_manager.pepper_exists():
            return True
        
        # Pepper missing - show recovery dialog
        dialog = SeedPhraseRecoveryDialog(self)
        result = dialog.exec()
        
        if result and dialog.recovered_pepper:
            return True
        
        return False
    
    def _handle_login(self):
        """Handle login button click."""
        username = self.login_username.text().strip()
        auth_pass = self.login_auth_pass.text()
        master_pass = self.login_master_pass.text()
        
        if not username or not auth_pass or not master_pass:
            self._show_status("Please fill in all fields")
            return
        
        # Check if pepper exists or needs recovery
        if not self._check_pepper_or_recover():
            self._show_status("Recovery seed required to decrypt your vault")
            return
        
        self._clear_status()
        self.login_btn.setEnabled(False)
        self.login_btn.setText("Logging in...")
        
        self.worker = AuthWorker("login", self.session, username, auth_pass, master_pass)
        self.worker.finished.connect(self._on_auth_finished)
        self.worker.start()
    
    def _handle_register(self):
        """Handle registration button click."""
        username = self.reg_username.text().strip()
        auth_pass = self.reg_auth_pass.text()
        master_pass = self.reg_master_pass.text()
        master_confirm = self.reg_master_confirm.text()
        
        if not username or not auth_pass or not master_pass:
            self._show_status("Please fill in all fields")
            return
        
        if len(username) < 3:
            self._show_status("Username must be at least 3 characters")
            return
        
        if len(auth_pass) < 8:
            self._show_status("Server password must be at least 8 characters")
            return
        
        if master_pass != master_confirm:
            self._show_status("Master passwords do not match")
            return
        
        if len(master_pass) < 8:
            self._show_status("Master password must be at least 8 characters")
            return
        
        self._clear_status()
        
        # Check if pepper already exists
        if self.pepper_manager.pepper_exists():
            # Pepper exists, proceed with registration
            self._do_register(username, auth_pass, master_pass)
        else:
            # Generate new pepper and show seed phrase dialog
            pepper = self.pepper_manager.generate_pepper()
            seed_phrase = self.pepper_manager.pepper_to_seed_phrase(pepper)
            
            # Store registration data for after dialog
            self._pending_registration = {
                'username': username,
                'auth_pass': auth_pass,
                'master_pass': master_pass,
                'pepper': pepper,
            }
            
            # Show seed phrase dialog
            dialog = SeedPhraseDisplayDialog(seed_phrase, self)
            result = dialog.exec()
            
            if result and dialog.confirmed:
                # User confirmed saving the seed phrase
                # Save pepper to file
                self.pepper_manager.save_pepper(pepper)
                
                # Proceed with registration
                self._do_register(username, auth_pass, master_pass)
            else:
                # User cancelled - clear pending registration
                self._pending_registration = None
                self._show_status("Registration cancelled - seed phrase not saved")
    
    def _do_register(self, username: str, auth_pass: str, master_pass: str):
        """Actually perform the registration after seed phrase is saved."""
        self.reg_btn.setEnabled(False)
        self.reg_btn.setText("Creating account...")
        
        self.worker = AuthWorker("register", self.session, username, auth_pass, master_pass)
        self.worker.finished.connect(self._on_auth_finished)
        self.worker.start()
    
    def _handle_offline_login(self):
        """Handle offline login button click."""
        username = self.offline_username.text().strip()
        master_pass = self.offline_master_pass.text()
        
        if not username or not master_pass:
            self._show_status("Please fill in all fields")
            return
        
        self._clear_status()
        
        self.worker = AuthWorker("offline", self.session, username, "", master_pass)
        self.worker.finished.connect(self._on_auth_finished)
        self.worker.start()
    
    def _handle_load_backup(self):
        """Handle loading a backup file."""
        file_path, _ = QFileDialog.getOpenFileName(
            self,
            "Load Vault Backup",
            "",
            "Backup Files (*.backup);;All Files (*)",
        )
        
        if not file_path:
            return
        
        # Show password dialog
        master_pass = self.offline_master_pass.text()
        if not master_pass:
            self._show_status("Please enter your master password first")
            return
        
        self._clear_status()
        
        self.worker = AuthWorker("backup", self.session, "", "", master_pass, file_path)
        self.worker.finished.connect(self._on_auth_finished)
        self.worker.start()
    
    def _on_auth_finished(self, success: bool, message: str):
        """Handle authentication completion."""
        # Reset buttons
        self.login_btn.setEnabled(True)
        self.login_btn.setText("Login")
        self.reg_btn.setEnabled(True)
        self.reg_btn.setText("Create Account")
        
        if success:
            self._show_status(message, is_error=False)
            self.login_successful.emit()
        else:
            self._show_status(message, is_error=True)
