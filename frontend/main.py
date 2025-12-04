"""Main application entry point for the password manager."""

from __future__ import annotations

import sys

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QApplication, QMainWindow, QStackedWidget

from .styles import STYLESHEET
from .session_manager import SessionManager
from .screens.auth_screen import AuthScreen
from .screens.dashboard_screen import DashboardScreen


class MainWindow(QMainWindow):
    """Main application window."""
    
    def __init__(self):
        super().__init__()
        self.session = SessionManager()
        self._setup_ui()
    
    def _setup_ui(self):
        """Setup the main window UI."""
        self.setWindowTitle("Proton Vault - Password Manager")
        self.setMinimumSize(1200, 800)
        self.resize(1400, 900)
        
        # Central widget with stacked pages
        self.stack = QStackedWidget()
        self.setCentralWidget(self.stack)
        
        # Auth screen
        self.auth_screen = AuthScreen(self.session)
        self.auth_screen.login_successful.connect(self._on_login_success)
        self.stack.addWidget(self.auth_screen)
        
        # Dashboard will be created after login
        self.dashboard_screen = None
    
    def _on_login_success(self):
        """Handle successful login."""
        # Create dashboard with session
        if self.dashboard_screen:
            self.stack.removeWidget(self.dashboard_screen)
            self.dashboard_screen.deleteLater()
        
        self.dashboard_screen = DashboardScreen(self.session)
        self.dashboard_screen.logout_requested.connect(self._on_logout)
        self.stack.addWidget(self.dashboard_screen)
        self.stack.setCurrentWidget(self.dashboard_screen)
    
    def _on_logout(self):
        """Handle logout."""
        self.stack.setCurrentWidget(self.auth_screen)
        
        if self.dashboard_screen:
            self.stack.removeWidget(self.dashboard_screen)
            self.dashboard_screen.deleteLater()
            self.dashboard_screen = None


def main():
    """Application entry point."""
    # Enable high DPI scaling
    QApplication.setHighDpiScaleFactorRoundingPolicy(
        Qt.HighDpiScaleFactorRoundingPolicy.PassThrough
    )
    
    app = QApplication(sys.argv)
    app.setApplicationName("Proton Vault")
    app.setOrganizationName("CS5371 Cryptography")
    
    # Apply stylesheet
    app.setStyleSheet(STYLESHEET)
    
    # Create and show main window
    window = MainWindow()
    window.show()
    
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
