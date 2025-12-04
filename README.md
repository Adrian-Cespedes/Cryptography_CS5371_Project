# Proton Vault - Password Manager

A secure, zero-knowledge password manager for the CS5371 Cryptography course.
Built with PySide6 (Qt) for the frontend, FastAPI for the backend, and strong
cryptographic primitives (Argon2id, AES-256-GCM).

## 🔐 Security Features

- **Argon2id Key Derivation**: Memory-hard password hashing (64MB, 3 iterations)
- **AES-256-GCM Encryption**: Authenticated encryption for vault data
- **Salt Rotation**: New salt generated on every vault modification
- **Pepper**: Application-level secret for additional security
- **Zero-Knowledge Architecture**: Server only stores encrypted blobs
- **Local Backup**: Encrypted backups in `~/.proton_vault/backups/`

## 📋 Requirements

- Python 3.10 or higher
- pip package manager

## 🚀 Installation

1. Install dependencies:

```bash
pip install -r requirements.txt
```

## ▶️ Running the Application

### Start the Backend Server

```bash
cd /path/to/project
PYTHONPATH=. python -m uvicorn backend.main:app --reload --port 8000
```

Or using fish shell:
```fish
cd /path/to/project
set -x PYTHONPATH .
python -m uvicorn backend.main:app --reload --port 8000
```

The API will be available at `http://localhost:8000`
- API docs: `http://localhost:8000/docs`

### Start the Frontend Application

In a new terminal:

```bash
cd /path/to/project
PYTHONPATH=. python -m frontend.main
```

Or using fish shell:
```fish
cd /path/to/project
set -x PYTHONPATH .
python -m frontend.main
```

## 📁 Project Structure

```
├── backend/                 # FastAPI server
│   ├── main.py             # API endpoints
│   ├── auth.py             # JWT authentication
│   ├── database.py         # SQLite database
│   └── schemas.py          # Pydantic models
├── frontend/               # PySide6 GUI application
│   ├── main.py             # Application entry point
│   ├── styles.py           # Proton-inspired styling
│   ├── api_client.py       # Backend API client
│   ├── backup_manager.py   # Local backup management
│   ├── session_manager.py  # Session & vault operations
│   └── screens/            # UI screens
│       ├── auth_screen.py          # Login/Register
│       ├── dashboard_screen.py     # Main vault view
│       └── password_generator_dialog.py
├── shared/                 # Shared modules
│   ├── crypto.py           # Cryptographic operations
│   ├── models.py           # Data models
│   └── password_generator.py
├── diagram.md              # Cryptographic architecture diagram
└── requirements.txt        # Dependencies
```

## 🔒 Cryptographic Architecture

See `diagram.md` for a detailed Mermaid diagram of the cryptographic flow.

| Component | Algorithm | Parameters |
|-----------|-----------|------------|
| Key Derivation | Argon2id | memory=64MB, time=3, parallelism=4 |
| Vault Encryption | AES-256-GCM | 96-bit IV, 128-bit auth tag |
| Salt | CSPRNG | 16 bytes, regenerated per modification |
| Vault Key | CSPRNG | 32 bytes (256-bit) |

## 🎯 Features

- ✅ User registration and login
- ✅ Master password-based encryption
- ✅ Add, edit, delete vault items
- ✅ Search functionality
- ✅ Password generator with strength indicator
- ✅ Copy passwords to clipboard
- ✅ Local encrypted backups
- ✅ Offline mode support
- ✅ Modern Proton Pass-inspired UI

## 📝 Usage

1. **Register**: Create an account with a username, server password, and master password
2. **Login**: Enter your credentials to access your vault
3. **Add Items**: Click "+ Add" to create new credential entries
4. **Edit/Delete**: Select an item to view, edit, or delete it
5. **Generate Password**: Use the 🎲 button to generate secure passwords
6. **Export Backup**: Click "Export" to save an encrypted backup file
7. **Offline Mode**: If the server is unavailable, login using local backups

## ⚠️ Important Notes

- **Master Password**: Cannot be recovered. Store it safely!
- **Backups**: Automatically saved to `~/.proton_vault/backups/`
- **Server Password**: Used for server authentication (separate from master password)

## 📄 License

MIT License - See LICENSE file
