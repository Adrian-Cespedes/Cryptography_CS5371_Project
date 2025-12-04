"""Proton Pass-inspired styling for the password manager."""

# Color Palette (Proton-inspired dark theme)
COLORS = {
    # Primary colors
    "primary": "#6D4AFF",  # Proton purple
    "primary_hover": "#8B6FFF",
    "primary_dark": "#4A2FCC",
    
    # Background colors
    "bg_dark": "#1A1A2E",
    "bg_medium": "#16213E",
    "bg_light": "#0F3460",
    "bg_card": "#1F2937",
    "bg_input": "#374151",
    
    # Text colors
    "text_primary": "#FFFFFF",
    "text_secondary": "#9CA3AF",
    "text_muted": "#6B7280",
    
    # Accent colors
    "success": "#10B981",
    "warning": "#F59E0B",
    "error": "#EF4444",
    "info": "#3B82F6",
    
    # Border colors
    "border": "#374151",
    "border_light": "#4B5563",
    
    # Item colors (for vault items)
    "item_hover": "#2D3748",
    "item_selected": "#3730A3",
}


# Global stylesheet for the application
STYLESHEET = f"""
/* Main Window */
QMainWindow {{
    background-color: {COLORS['bg_dark']};
}}

QWidget {{
    background-color: transparent;
    color: {COLORS['text_primary']};
    font-family: 'Segoe UI', 'SF Pro Display', -apple-system, BlinkMacSystemFont, sans-serif;
    font-size: 14px;
}}

/* Frames and Containers */
QFrame {{
    background-color: {COLORS['bg_card']};
    border-radius: 8px;
    border: 1px solid {COLORS['border']};
}}

QFrame#sidebar {{
    background-color: {COLORS['bg_medium']};
    border-right: 1px solid {COLORS['border']};
    border-radius: 0;
}}

QFrame#header {{
    background-color: {COLORS['bg_medium']};
    border-bottom: 1px solid {COLORS['border']};
    border-radius: 0;
}}

/* Labels */
QLabel {{
    color: {COLORS['text_primary']};
    background-color: transparent;
    border: none;
}}

QLabel#title {{
    font-size: 24px;
    font-weight: 600;
    color: {COLORS['text_primary']};
}}

QLabel#subtitle {{
    font-size: 14px;
    color: {COLORS['text_secondary']};
}}

QLabel#section_title {{
    font-size: 16px;
    font-weight: 600;
    color: {COLORS['text_primary']};
}}

/* Buttons */
QPushButton {{
    background-color: {COLORS['primary']};
    color: {COLORS['text_primary']};
    border: none;
    border-radius: 6px;
    padding: 10px 20px;
    font-weight: 500;
    font-size: 14px;
}}

QPushButton:hover {{
    background-color: {COLORS['primary_hover']};
}}

QPushButton:pressed {{
    background-color: {COLORS['primary_dark']};
}}

QPushButton:disabled {{
    background-color: {COLORS['bg_input']};
    color: {COLORS['text_muted']};
}}

QPushButton#secondary {{
    background-color: transparent;
    border: 1px solid {COLORS['border_light']};
    color: {COLORS['text_secondary']};
}}

QPushButton#secondary:hover {{
    background-color: {COLORS['bg_input']};
    color: {COLORS['text_primary']};
}}

QPushButton#danger {{
    background-color: {COLORS['error']};
}}

QPushButton#danger:hover {{
    background-color: #DC2626;
}}

QPushButton#icon_button {{
    background-color: transparent;
    border: none;
    padding: 8px;
    border-radius: 4px;
}}

QPushButton#icon_button:hover {{
    background-color: {COLORS['bg_input']};
}}

/* Input Fields */
QLineEdit {{
    background-color: {COLORS['bg_input']};
    color: {COLORS['text_primary']};
    border: 1px solid {COLORS['border']};
    border-radius: 6px;
    padding: 10px 12px;
    font-size: 14px;
    selection-background-color: {COLORS['primary']};
}}

QLineEdit:focus {{
    border: 1px solid {COLORS['primary']};
}}

QLineEdit:disabled {{
    background-color: {COLORS['bg_dark']};
    color: {COLORS['text_muted']};
}}

QLineEdit[echoMode="2"] {{
    lineedit-password-character: 9679;
}}

/* Text Areas */
QTextEdit, QPlainTextEdit {{
    background-color: {COLORS['bg_input']};
    color: {COLORS['text_primary']};
    border: 1px solid {COLORS['border']};
    border-radius: 6px;
    padding: 10px;
    font-size: 14px;
    selection-background-color: {COLORS['primary']};
}}

QTextEdit:focus, QPlainTextEdit:focus {{
    border: 1px solid {COLORS['primary']};
}}

/* List Widget */
QListWidget {{
    background-color: transparent;
    border: none;
    outline: none;
}}

QListWidget::item {{
    background-color: {COLORS['bg_card']};
    color: {COLORS['text_primary']};
    border-radius: 8px;
    padding: 12px;
    margin: 4px 8px;
}}

QListWidget::item:hover {{
    background-color: {COLORS['item_hover']};
}}

QListWidget::item:selected {{
    background-color: {COLORS['item_selected']};
}}

/* Scroll Areas */
QScrollArea {{
    background-color: transparent;
    border: none;
}}

QScrollBar:vertical {{
    background-color: transparent;
    width: 8px;
    margin: 0;
}}

QScrollBar::handle:vertical {{
    background-color: {COLORS['border_light']};
    border-radius: 4px;
    min-height: 30px;
}}

QScrollBar::handle:vertical:hover {{
    background-color: {COLORS['text_muted']};
}}

QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{
    height: 0;
}}

QScrollBar::add-page:vertical, QScrollBar::sub-page:vertical {{
    background: transparent;
}}

QScrollBar:horizontal {{
    background-color: transparent;
    height: 8px;
    margin: 0;
}}

QScrollBar::handle:horizontal {{
    background-color: {COLORS['border_light']};
    border-radius: 4px;
    min-width: 30px;
}}

/* Checkboxes */
QCheckBox {{
    color: {COLORS['text_primary']};
    spacing: 8px;
}}

QCheckBox::indicator {{
    width: 18px;
    height: 18px;
    border-radius: 4px;
    border: 1px solid {COLORS['border_light']};
    background-color: {COLORS['bg_input']};
}}

QCheckBox::indicator:checked {{
    background-color: {COLORS['primary']};
    border-color: {COLORS['primary']};
}}

/* Sliders */
QSlider::groove:horizontal {{
    background: {COLORS['bg_input']};
    height: 6px;
    border-radius: 3px;
}}

QSlider::handle:horizontal {{
    background: {COLORS['primary']};
    width: 16px;
    height: 16px;
    margin: -5px 0;
    border-radius: 8px;
}}

QSlider::sub-page:horizontal {{
    background: {COLORS['primary']};
    border-radius: 3px;
}}

/* Progress Bar */
QProgressBar {{
    background-color: {COLORS['bg_input']};
    border: none;
    border-radius: 4px;
    height: 8px;
    text-align: center;
}}

QProgressBar::chunk {{
    background-color: {COLORS['primary']};
    border-radius: 4px;
}}

/* Tab Widget */
QTabWidget::pane {{
    background-color: {COLORS['bg_card']};
    border: 1px solid {COLORS['border']};
    border-radius: 8px;
}}

QTabBar::tab {{
    background-color: transparent;
    color: {COLORS['text_secondary']};
    padding: 10px 20px;
    margin-right: 4px;
    border-bottom: 2px solid transparent;
}}

QTabBar::tab:selected {{
    color: {COLORS['primary']};
    border-bottom: 2px solid {COLORS['primary']};
}}

QTabBar::tab:hover {{
    color: {COLORS['text_primary']};
}}

/* Message Box / Dialog */
QMessageBox {{
    background-color: {COLORS['bg_card']};
}}

QMessageBox QLabel {{
    color: {COLORS['text_primary']};
}}

QMessageBox QPushButton {{
    min-width: 80px;
}}

/* Tooltips */
QToolTip {{
    background-color: {COLORS['bg_light']};
    color: {COLORS['text_primary']};
    border: 1px solid {COLORS['border']};
    border-radius: 4px;
    padding: 6px;
}}

/* Combo Box */
QComboBox {{
    background-color: {COLORS['bg_input']};
    color: {COLORS['text_primary']};
    border: 1px solid {COLORS['border']};
    border-radius: 6px;
    padding: 8px 12px;
}}

QComboBox:focus {{
    border: 1px solid {COLORS['primary']};
}}

QComboBox::drop-down {{
    border: none;
    width: 24px;
}}

QComboBox QAbstractItemView {{
    background-color: {COLORS['bg_card']};
    color: {COLORS['text_primary']};
    border: 1px solid {COLORS['border']};
    selection-background-color: {COLORS['primary']};
}}

/* Spin Box */
QSpinBox {{
    background-color: {COLORS['bg_input']};
    color: {COLORS['text_primary']};
    border: 1px solid {COLORS['border']};
    border-radius: 6px;
    padding: 8px 12px;
}}

QSpinBox:focus {{
    border: 1px solid {COLORS['primary']};
}}
"""
