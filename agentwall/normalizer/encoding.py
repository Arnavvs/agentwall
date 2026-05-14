from __future__ import annotations

import base64
import codecs
import re
from dataclasses import dataclass

BASE64_RE = re.compile(r"[A-Za-z0-9+/]{16,}={0,2}")
HEX_RE = re.compile(r"(?:[0-9a-fA-F]{2}){8,}")


@dataclass(frozen=True)
class DecodedVariant:
    text: str
    method: str


def try_base64_decode(text: str) -> list[DecodedVariant]:
    variants: list[DecodedVariant] = []
    for match in BASE64_RE.finditer(text):
        candidate = match.group()
        try:
            padding = 4 - (len(candidate) % 4)
            if padding != 4:
                candidate_padded = candidate + "=" * padding
            else:
                candidate_padded = candidate
            decoded = base64.b64decode(candidate_padded)
            decoded_str = decoded.decode("utf-8")
            if decoded_str and decoded_str.isprintable() or any(c.isalpha() for c in decoded_str):
                variants.append(DecodedVariant(text=decoded_str, method="base64"))
        except Exception:
            continue
    return variants


def try_rot13_decode(text: str) -> str | None:
    decoded = codecs.decode(text, "rot_13")
    if decoded == text:
        return None
    return decoded


def try_hex_decode(text: str) -> list[DecodedVariant]:
    variants: list[DecodedVariant] = []
    for match in HEX_RE.finditer(text):
        candidate = match.group()
        try:
            decoded = bytes.fromhex(candidate).decode("utf-8")
            if decoded and any(c.isalpha() for c in decoded):
                variants.append(DecodedVariant(text=decoded, method="hex"))
        except (ValueError, UnicodeDecodeError):
            continue
    return variants
