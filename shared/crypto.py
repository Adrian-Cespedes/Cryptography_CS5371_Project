"""Cryptographic operations for the password manager.

This module implements:
- Argon2id key derivation with salt and pepper
- AES-256-GCM encryption/decryption
- Vault key generation using CSPRNG
- Salt regeneration on every vault modification
- User-specific pepper (recovery seed) generation and management
"""

from __future__ import annotations

import base64
import os
import secrets
from dataclasses import dataclass
from pathlib import Path
from typing import Tuple, Optional, List

from argon2.low_level import hash_secret_raw, Type
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from .models import Vault, EncryptedBlob


# Pepper configuration
PEPPER_SIZE = 32  # 256-bit pepper
PEPPER_DIR = Path.home() / ".proton_vault"
PEPPER_FILE = PEPPER_DIR / "pepper.key"

# BIP39-like wordlist for human-readable seed phrases (subset of 256 words)
SEED_WORDLIST = [
    "abandon", "ability", "able", "about", "above", "absent", "absorb", "abstract",
    "absurd", "abuse", "access", "accident", "account", "accuse", "achieve", "acid",
    "acoustic", "acquire", "across", "act", "action", "actor", "actress", "actual",
    "adapt", "add", "addict", "address", "adjust", "admit", "adult", "advance",
    "advice", "aerobic", "affair", "afford", "afraid", "again", "age", "agent",
    "agree", "ahead", "aim", "air", "airport", "aisle", "alarm", "album",
    "alcohol", "alert", "alien", "all", "alley", "allow", "almost", "alone",
    "alpha", "already", "also", "alter", "always", "amateur", "amazing", "among",
    "amount", "amused", "analyst", "anchor", "ancient", "anger", "angle", "angry",
    "animal", "ankle", "announce", "annual", "another", "answer", "antenna", "antique",
    "anxiety", "any", "apart", "apology", "appear", "apple", "approve", "april",
    "arch", "arctic", "area", "arena", "argue", "arm", "armed", "armor",
    "army", "around", "arrange", "arrest", "arrive", "arrow", "art", "artefact",
    "artist", "artwork", "ask", "aspect", "assault", "asset", "assist", "assume",
    "asthma", "athlete", "atom", "attack", "attend", "attitude", "attract", "auction",
    "audit", "august", "aunt", "author", "auto", "autumn", "average", "avocado",
    "avoid", "awake", "aware", "away", "awesome", "awful", "awkward", "axis",
    "baby", "bachelor", "bacon", "badge", "bag", "balance", "balcony", "ball",
    "bamboo", "banana", "banner", "bar", "barely", "bargain", "barrel", "base",
    "basic", "basket", "battle", "beach", "bean", "beauty", "because", "become",
    "beef", "before", "begin", "behave", "behind", "believe", "below", "belt",
    "bench", "benefit", "best", "betray", "better", "between", "beyond", "bicycle",
    "bid", "bike", "bind", "biology", "bird", "birth", "bitter", "black",
    "blade", "blame", "blanket", "blast", "bleak", "bless", "blind", "blood",
    "blossom", "blouse", "blue", "blur", "blush", "board", "boat", "body",
    "boil", "bomb", "bone", "bonus", "book", "boost", "border", "boring",
    "borrow", "boss", "bottom", "bounce", "box", "boy", "bracket", "brain",
    "brand", "brass", "brave", "bread", "breeze", "brick", "bridge", "brief",
    "bright", "bring", "brisk", "broccoli", "broken", "bronze", "broom", "brother",
    "brown", "brush", "bubble", "buddy", "budget", "buffalo", "build", "bulb",
    "bulk", "bullet", "bundle", "bunker", "burden", "burger", "burst", "bus",
    "business", "busy", "butter", "buyer", "buzz", "cabbage", "cabin", "cable",
]


class PepperManager:
    """Manages pepper (recovery seed) generation, storage, and retrieval."""
    
    def __init__(self, pepper_dir: Optional[Path] = None):
        self.pepper_dir = pepper_dir or PEPPER_DIR
        self.pepper_file = self.pepper_dir / "pepper.key"
    
    def generate_pepper(self) -> bytes:
        """Generate a new cryptographically secure pepper."""
        return secrets.token_bytes(PEPPER_SIZE)
    
    def pepper_to_seed_phrase(self, pepper: bytes) -> List[str]:
        """Convert pepper bytes to a human-readable seed phrase.
        
        Uses a BIP39-like approach: each byte maps to a word from the wordlist.
        32 bytes = 32 words.
        """
        return [SEED_WORDLIST[b] for b in pepper]
    
    def seed_phrase_to_pepper(self, seed_phrase: List[str]) -> bytes:
        """Convert a seed phrase back to pepper bytes.
        
        Args:
            seed_phrase: List of 32 words from the wordlist
            
        Returns:
            32-byte pepper
            
        Raises:
            ValueError: If any word is not in the wordlist or wrong length
        """
        if len(seed_phrase) != PEPPER_SIZE:
            raise ValueError(f"Seed phrase must be exactly {PEPPER_SIZE} words")
        
        word_to_index = {word: i for i, word in enumerate(SEED_WORDLIST)}
        
        pepper_bytes = []
        for word in seed_phrase:
            word_lower = word.lower().strip()
            if word_lower not in word_to_index:
                raise ValueError(f"Invalid word in seed phrase: '{word}'")
            pepper_bytes.append(word_to_index[word_lower])
        
        return bytes(pepper_bytes)
    
    def save_pepper(self, pepper: bytes) -> None:
        """Save pepper to local file.
        
        The pepper is stored as base64-encoded bytes.
        """
        self.pepper_dir.mkdir(parents=True, exist_ok=True)
        
        # Save as base64 for safe storage
        encoded = base64.b64encode(pepper).decode('utf-8')
        self.pepper_file.write_text(encoded)
        
        # Set restrictive permissions (owner read/write only)
        try:
            os.chmod(self.pepper_file, 0o600)
        except OSError:
            pass  # Windows doesn't support Unix permissions
    
    def load_pepper(self) -> Optional[bytes]:
        """Load pepper from local file.
        
        Returns:
            Pepper bytes if file exists and is valid, None otherwise
        """
        if not self.pepper_file.exists():
            return None
        
        try:
            encoded = self.pepper_file.read_text().strip()
            pepper = base64.b64decode(encoded)
            
            if len(pepper) != PEPPER_SIZE:
                return None
                
            return pepper
        except Exception:
            return None
    
    def pepper_exists(self) -> bool:
        """Check if a pepper file exists."""
        return self.pepper_file.exists()
    
    def delete_pepper(self) -> None:
        """Delete the pepper file (use with caution!)."""
        if self.pepper_file.exists():
            self.pepper_file.unlink()


@dataclass
class CryptoConfig:
    """Configuration for cryptographic operations."""

    # Argon2id parameters (OWASP recommendations)
    argon2_memory_cost: int = 65536  # 64 MB
    argon2_time_cost: int = 3  # 3 iterations
    argon2_parallelism: int = 4  # 4 threads
    argon2_hash_len: int = 32  # 256-bit key

    # AES-GCM parameters
    aes_key_size: int = 32  # 256-bit key
    aes_iv_size: int = 12  # 96-bit IV (recommended for GCM)
    aes_tag_size: int = 16  # 128-bit authentication tag

    # Salt size
    salt_size: int = 16  # 128-bit salt


class CryptoManager:
    """Manages all cryptographic operations for the password manager."""

    def __init__(self, pepper: bytes, config: Optional[CryptoConfig] = None):
        """Initialize CryptoManager with a user's pepper.
        
        Args:
            pepper: User's 32-byte pepper (recovery seed)
            config: Optional crypto configuration
            
        Raises:
            ValueError: If pepper is not exactly 32 bytes
        """
        if len(pepper) != PEPPER_SIZE:
            raise ValueError(f"Pepper must be exactly {PEPPER_SIZE} bytes")
        
        self.config = config or CryptoConfig()
        self._pepper = pepper

    def generate_salt(self) -> bytes:
        """Generate a cryptographically secure random salt.
        
        This should be called every time the vault is modified.
        """
        return secrets.token_bytes(self.config.salt_size)

    def generate_vault_key(self) -> bytes:
        """Generate a new vault key using CSPRNG.
        
        This key is used to encrypt the vault data and is itself
        encrypted with the master key derived from the user's password.
        """
        return secrets.token_bytes(self.config.aes_key_size)

    def derive_master_key(self, password: str, salt: bytes) -> bytes:
        """Derive a master key from the user's password using Argon2id.
        
        The master key is used to encrypt/decrypt the vault key.
        
        Args:
            password: User's master password
            salt: Random salt (should be unique per user/session)
            
        Returns:
            32-byte derived key
        """
        # Combine password with pepper for additional security
        password_with_pepper = password.encode("utf-8") + self._pepper

        # Use Argon2id (hybrid of Argon2i and Argon2d)
        # Provides resistance against both side-channel and GPU attacks
        derived_key = hash_secret_raw(
            secret=password_with_pepper,
            salt=salt,
            time_cost=self.config.argon2_time_cost,
            memory_cost=self.config.argon2_memory_cost,
            parallelism=self.config.argon2_parallelism,
            hash_len=self.config.argon2_hash_len,
            type=Type.ID,  # Argon2id
        )

        return derived_key

    def _encrypt_aes_gcm(
        self, key: bytes, plaintext: bytes, associated_data: bytes = b""
    ) -> Tuple[bytes, bytes, bytes]:
        """Encrypt data using AES-256-GCM.
        
        Args:
            key: 32-byte encryption key
            plaintext: Data to encrypt
            associated_data: Additional data to authenticate (not encrypted)
            
        Returns:
            Tuple of (iv, ciphertext, auth_tag)
        """
        # Generate random IV (nonce)
        iv = os.urandom(self.config.aes_iv_size)

        # Create cipher
        cipher = Cipher(algorithms.AES(key), modes.GCM(iv))
        encryptor = cipher.encryptor()

        # Authenticate additional data
        if associated_data:
            encryptor.authenticate_additional_data(associated_data)

        # Encrypt
        ciphertext = encryptor.update(plaintext) + encryptor.finalize()

        return iv, ciphertext, encryptor.tag

    def _decrypt_aes_gcm(
        self,
        key: bytes,
        iv: bytes,
        ciphertext: bytes,
        auth_tag: bytes,
        associated_data: bytes = b"",
    ) -> bytes:
        """Decrypt data using AES-256-GCM.
        
        Args:
            key: 32-byte decryption key
            iv: Initialization vector used during encryption
            ciphertext: Encrypted data
            auth_tag: Authentication tag for verification
            associated_data: Additional data that was authenticated
            
        Returns:
            Decrypted plaintext
            
        Raises:
            cryptography.exceptions.InvalidTag: If authentication fails
        """
        cipher = Cipher(algorithms.AES(key), modes.GCM(iv, auth_tag))
        decryptor = cipher.decryptor()

        if associated_data:
            decryptor.authenticate_additional_data(associated_data)

        plaintext = decryptor.update(ciphertext) + decryptor.finalize()

        return plaintext

    def encrypt_vault_key(
        self, vault_key: bytes, master_key: bytes
    ) -> Tuple[bytes, bytes, bytes]:
        """Encrypt the vault key with the master key.
        
        Args:
            vault_key: The vault encryption key to protect
            master_key: Key derived from user's password
            
        Returns:
            Tuple of (iv, encrypted_vault_key, auth_tag)
        """
        return self._encrypt_aes_gcm(master_key, vault_key, b"vault_key")

    def decrypt_vault_key(
        self,
        encrypted_vault_key: bytes,
        master_key: bytes,
        iv: bytes,
        auth_tag: bytes,
    ) -> bytes:
        """Decrypt the vault key using the master key.
        
        Args:
            encrypted_vault_key: The encrypted vault key
            master_key: Key derived from user's password
            iv: IV used during encryption
            auth_tag: Authentication tag
            
        Returns:
            The decrypted vault key
        """
        return self._decrypt_aes_gcm(
            master_key, iv, encrypted_vault_key, auth_tag, b"vault_key"
        )

    def encrypt_vault(self, vault: Vault, vault_key: bytes) -> Tuple[bytes, bytes, bytes]:
        """Encrypt the vault data.
        
        Args:
            vault: The vault to encrypt
            vault_key: Key used for encryption
            
        Returns:
            Tuple of (iv, ciphertext, auth_tag)
        """
        plaintext = vault.to_json().encode("utf-8")
        return self._encrypt_aes_gcm(vault_key, plaintext, b"vault_data")

    def decrypt_vault(
        self, ciphertext: bytes, vault_key: bytes, iv: bytes, auth_tag: bytes
    ) -> Vault:
        """Decrypt the vault data.
        
        Args:
            ciphertext: Encrypted vault data
            vault_key: Key used for decryption
            iv: IV used during encryption
            auth_tag: Authentication tag
            
        Returns:
            Decrypted Vault object
        """
        plaintext = self._decrypt_aes_gcm(
            vault_key, iv, ciphertext, auth_tag, b"vault_data"
        )
        return Vault.from_json(plaintext.decode("utf-8"))

    def create_encrypted_blob(
        self, vault: Vault, password: str, existing_vault_key: Optional[bytes] = None
    ) -> Tuple[EncryptedBlob, bytes, bytes]:
        """Create an encrypted blob from a vault.
        
        This method:
        1. Generates a new salt (for forward secrecy)
        2. Derives a master key from the password
        3. Uses existing vault key or generates a new one
        4. Encrypts the vault with the vault key
        5. Encrypts the vault key with the master key
        
        Args:
            vault: The vault to encrypt
            password: User's master password
            existing_vault_key: Existing vault key (for updates) or None (for new vaults)
            
        Returns:
            Tuple of (encrypted_blob, vault_key, salt)
        """
        # Generate new salt for each encryption (forward secrecy)
        salt = self.generate_salt()

        # Derive master key
        master_key = self.derive_master_key(password, salt)

        # Use existing vault key or generate new one
        vault_key = existing_vault_key or self.generate_vault_key()

        # Encrypt vault data
        vault_iv, vault_ciphertext, vault_tag = self.encrypt_vault(vault, vault_key)

        # Encrypt vault key with master key
        vk_iv, encrypted_vk, vk_tag = self.encrypt_vault_key(vault_key, master_key)

        # Create the blob
        blob = EncryptedBlob(
            ciphertext=base64.b64encode(vault_ciphertext).decode("ascii"),
            iv=base64.b64encode(vault_iv).decode("ascii"),
            auth_tag=base64.b64encode(vault_tag).decode("ascii"),
            salt=base64.b64encode(salt).decode("ascii"),
            encrypted_vault_key=base64.b64encode(encrypted_vk).decode("ascii"),
            vault_key_iv=base64.b64encode(vk_iv).decode("ascii"),
            vault_key_auth_tag=base64.b64encode(vk_tag).decode("ascii"),
        )

        return blob, vault_key, salt

    def decrypt_encrypted_blob(
        self, blob: EncryptedBlob, password: str
    ) -> Tuple[Vault, bytes]:
        """Decrypt an encrypted blob to retrieve the vault.
        
        Args:
            blob: The encrypted blob
            password: User's master password
            
        Returns:
            Tuple of (decrypted_vault, vault_key)
            
        Raises:
            cryptography.exceptions.InvalidTag: If password is wrong or data is tampered
        """
        # Decode base64 values
        salt = base64.b64decode(blob.salt)
        vault_iv = base64.b64decode(blob.iv)
        vault_ciphertext = base64.b64decode(blob.ciphertext)
        vault_tag = base64.b64decode(blob.auth_tag)
        encrypted_vk = base64.b64decode(blob.encrypted_vault_key)
        vk_iv = base64.b64decode(blob.vault_key_iv)
        vk_tag = base64.b64decode(blob.vault_key_auth_tag)

        # Derive master key from password and stored salt
        master_key = self.derive_master_key(password, salt)

        # Decrypt vault key
        vault_key = self.decrypt_vault_key(encrypted_vk, master_key, vk_iv, vk_tag)

        # Decrypt vault
        vault = self.decrypt_vault(vault_ciphertext, vault_key, vault_iv, vault_tag)

        return vault, vault_key

    def hash_password_for_auth(self, password: str, salt: bytes) -> str:
        """Hash password for server-side authentication.
        
        This is separate from the master key derivation and is used
        for authenticating with the server.
        
        Args:
            password: User's password
            salt: Salt for hashing
            
        Returns:
            Base64-encoded hash
        """
        # Use different pepper for auth to maintain separation
        auth_pepper = b"ProtonVaultAuthPepper2024Secret!"
        password_bytes = password.encode("utf-8") + auth_pepper

        hash_bytes = hash_secret_raw(
            secret=password_bytes,
            salt=salt,
            time_cost=self.config.argon2_time_cost,
            memory_cost=self.config.argon2_memory_cost,
            parallelism=self.config.argon2_parallelism,
            hash_len=self.config.argon2_hash_len,
            type=Type.ID,
        )

        return base64.b64encode(hash_bytes).decode("ascii")

    def verify_auth_password(
        self, password: str, salt: bytes, stored_hash: str
    ) -> bool:
        """Verify a password against a stored hash.
        
        Args:
            password: Password to verify
            salt: Salt used during hashing
            stored_hash: The stored hash to compare against
            
        Returns:
            True if password matches, False otherwise
        """
        computed_hash = self.hash_password_for_auth(password, salt)
        return secrets.compare_digest(computed_hash, stored_hash)
