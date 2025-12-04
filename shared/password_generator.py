"""Password generator utilities with secure random generation."""

from __future__ import annotations

import secrets
import string
from dataclasses import dataclass
from typing import Optional


@dataclass
class PasswordOptions:
    """Options for password generation."""

    length: int = 16
    include_lowercase: bool = True
    include_uppercase: bool = True
    include_numbers: bool = True
    include_symbols: bool = True
    exclude_ambiguous: bool = True
    custom_symbols: Optional[str] = None


class PasswordGenerator:
    """Secure password generator using cryptographically strong randomness."""

    # Exclude ambiguous characters that are often confused: 0, O, 1, l, I
    _AMBIGUOUS_CHARS = "0O1lI"

    # Default symbols that are commonly accepted
    _DEFAULT_SYMBOLS = "!@#$%^&*()_+-=[]{}|;:,.<>?"

    def __init__(self):
        self._lowercase = string.ascii_lowercase
        self._uppercase = string.ascii_uppercase
        self._numbers = string.digits
        self._symbols = self._DEFAULT_SYMBOLS

    def generate(self, options: PasswordOptions) -> str:
        """Generate a secure password based on the given options.

        Args:
            options: Configuration for password generation.

        Returns:
            A securely generated password string.

        Raises:
            ValueError: If no character sets are enabled or length < 1.
        """
        if options.length < 1:
            raise ValueError("Password length must be at least 1")

        # Use custom symbols if provided
        symbols = options.custom_symbols or self._symbols

        # Build character set
        charset = ""
        required_chars: list[str] = []

        if options.include_lowercase:
            chars = self._lowercase
            if options.exclude_ambiguous:
                chars = "".join(c for c in chars if c not in self._AMBIGUOUS_CHARS)
            charset += chars
            required_chars.append(secrets.choice(chars))

        if options.include_uppercase:
            chars = self._uppercase
            if options.exclude_ambiguous:
                chars = "".join(c for c in chars if c not in self._AMBIGUOUS_CHARS)
            charset += chars
            required_chars.append(secrets.choice(chars))

        if options.include_numbers:
            chars = self._numbers
            if options.exclude_ambiguous:
                chars = "".join(c for c in chars if c not in self._AMBIGUOUS_CHARS)
            charset += chars
            required_chars.append(secrets.choice(chars))

        if options.include_symbols:
            charset += symbols
            required_chars.append(secrets.choice(symbols))

        if not charset:
            raise ValueError("At least one character type must be selected")

        # Generate password ensuring at least one character from each required type
        password_chars = required_chars[:]

        # Fill remaining length with random characters
        remaining_length = max(0, options.length - len(required_chars))
        for _ in range(remaining_length):
            password_chars.append(secrets.choice(charset))

        # Shuffle to avoid predictable patterns
        secrets.SystemRandom().shuffle(password_chars)

        return "".join(password_chars[: options.length])

    def estimate_entropy(self, options: PasswordOptions) -> float:
        """Estimate the entropy (bits) of a password generated with given options.

        Args:
            options: Password generation options.

        Returns:
            Estimated entropy in bits.
        """
        import math

        charset_size = 0
        symbols = options.custom_symbols or self._symbols

        if options.include_lowercase:
            chars = self._lowercase
            if options.exclude_ambiguous:
                chars = "".join(c for c in chars if c not in self._AMBIGUOUS_CHARS)
            charset_size += len(chars)

        if options.include_uppercase:
            chars = self._uppercase
            if options.exclude_ambiguous:
                chars = "".join(c for c in chars if c not in self._AMBIGUOUS_CHARS)
            charset_size += len(chars)

        if options.include_numbers:
            chars = self._numbers
            if options.exclude_ambiguous:
                chars = "".join(c for c in chars if c not in self._AMBIGUOUS_CHARS)
            charset_size += len(chars)

        if options.include_symbols:
            charset_size += len(symbols)

        if charset_size == 0:
            return 0.0

        return options.length * math.log2(charset_size)

    def get_strength_label(self, entropy: float) -> str:
        """Get a human-readable strength label based on entropy.

        Args:
            entropy: Password entropy in bits.

        Returns:
            Strength label (Weak, Fair, Good, Strong, Very Strong).
        """
        if entropy < 28:
            return "Very Weak"
        elif entropy < 36:
            return "Weak"
        elif entropy < 60:
            return "Fair"
        elif entropy < 80:
            return "Good"
        elif entropy < 100:
            return "Strong"
        else:
            return "Very Strong"

    def get_strength_color(self, entropy: float) -> str:
        """Get a color for the strength indicator.

        Args:
            entropy: Password entropy in bits.

        Returns:
            Color hex code.
        """
        if entropy < 28:
            return "#ef4444"  # Red
        elif entropy < 36:
            return "#f97316"  # Orange
        elif entropy < 60:
            return "#eab308"  # Yellow
        elif entropy < 80:
            return "#84cc16"  # Lime
        elif entropy < 100:
            return "#22c55e"  # Green
        else:
            return "#10b981"  # Emerald
