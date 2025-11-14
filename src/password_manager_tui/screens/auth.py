"""Authentication screen for the password manager."""

from __future__ import annotations

from textual import on
from textual.app import ComposeResult
from textual.containers import Container
from textual.message import Message
from textual.screen import ModalScreen
from textual.widgets import Button, Input, Label, Static


class AuthCompleted(Message):
    """Message sent when authentication is completed."""

    def __init__(self, success: bool, username: str = "") -> None:
        self.success = success
        self.username = username
        super().__init__()


class AuthScreen(ModalScreen[dict]):
    """Authentication screen for login/register."""

    CSS = """
    AuthScreen {
        align: center middle;
    }

    .auth-dialog {
        width: 60;
        height: 20;
        background: $surface;
        border: thick $primary;
        padding: 1 2;
    }

    .auth-title {
        text-align: center;
        text-style: bold;
        margin-bottom: 1;
    }

    .input-field {
        margin: 1 0;
    }

    .button-row {
        layout: horizontal;
        height: 3;
        margin-top: 1;
    }

    .button-row Button {
        width: 1fr;
        margin: 0 1;
    }

    .toggle-button {
        text-align: center;
        margin-top: 1;
        color: $accent;
    }

    .error-text {
        color: $error;
        text-align: center;
        margin: 1 0;
    }
    """

    def __init__(self) -> None:
        super().__init__()
        self._is_login = True

    def compose(self) -> ComposeResult:
        with Container(classes="auth-dialog"):
            yield Static("Iniciar Sesión", id="auth-title", classes="auth-title")
            yield Label("Usuario:", classes="input-field")
            yield Input(placeholder="Ingrese su usuario", id="username", classes="input-field")
            yield Label("Contraseña Maestra:", classes="input-field")
            yield Input(placeholder="Ingrese su contraseña maestra", password=True, id="password", classes="input-field")
            yield Static("", id="error-message", classes="error-text")
            
            with Container(classes="button-row"):
                yield Button("Entrar", id="submit-btn", variant="primary")
                yield Button("Cancelar", id="cancel-btn", variant="default")
            
            yield Button("¿No tienes cuenta? Regístrate", id="toggle-btn", classes="toggle-button")

    def on_mount(self) -> None:
        self.query_one("#username", Input).focus()

    @on(Button.Pressed, "#submit-btn")
    def handle_submit(self, event: Button.Pressed) -> None:
        username = self.query_one("#username", Input).value.strip()
        password = self.query_one("#password", Input).value
        
        if not username or not password:
            self._show_error("Por favor complete todos los campos")
            return

        if self._is_login:
            # Simulate login validation
            if username and password:
                # For now, accept any non-empty credentials
                self.post_message(AuthCompleted(True, username))
                self.dismiss({"success": True, "username": username})
            else:
                self._show_error("Credenciales inválidas")
        else:
            # Register new user
            if len(password) < 6:
                self._show_error("La contraseña debe tener al menos 6 caracteres")
                return
            
            # Simulate successful registration
            self.post_message(AuthCompleted(True, username))
            self.dismiss({"success": True, "username": username})

    @on(Button.Pressed, "#cancel-btn")
    def handle_cancel(self, event: Button.Pressed) -> None:
        self.post_message(AuthCompleted(False))
        self.dismiss({"success": False})

    @on(Button.Pressed, "#toggle-btn")
    def handle_toggle(self, event: Button.Pressed) -> None:
        self._is_login = not self._is_login
        
        title_widget = self.query_one("#auth-title", Static)
        toggle_widget = self.query_one("#toggle-btn", Button)
        
        if self._is_login:
            title_widget.update("Iniciar Sesión")
            toggle_widget.label = "¿No tienes cuenta? Regístrate"
        else:
            title_widget.update("Crear Cuenta")
            toggle_widget.label = "¿Ya tienes cuenta? Inicia sesión"
        
        # Clear error message and input fields
        self._show_error("")
        self.query_one("#username", Input).value = ""
        self.query_one("#password", Input).value = ""
        self.query_one("#username", Input).focus()

    def _show_error(self, message: str) -> None:
        self.query_one("#error-message", Static).update(message)