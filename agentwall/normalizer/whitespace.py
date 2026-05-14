from __future__ import annotations

import re


def collapse_whitespace(text: str) -> str:
    text = re.sub(r"[ \t]+", " ", text)
    text = text.strip()
    return text
