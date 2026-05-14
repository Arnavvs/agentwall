from __future__ import annotations

import unicodedata


def normalize_unicode(text: str) -> str:
    text = unicodedata.normalize("NFKC", text)
    cleaned = []
    for ch in text:
        cat = unicodedata.category(ch)
        if cat == "Cf":
            continue
        if cat.startswith("C") and ch not in ("\n", "\t", "\r"):
            continue
        cleaned.append(ch)
    return "".join(cleaned)
