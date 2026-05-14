from __future__ import annotations

import json
import re


def flatten_json(text: str) -> str | None:
    try:
        data = json.loads(text)
    except (json.JSONDecodeError, TypeError):
        return None
    return _extract_json_strings(data)


def _extract_json_strings(obj: object) -> str:
    parts: list[str] = []
    if isinstance(obj, str):
        parts.append(obj)
    elif isinstance(obj, dict):
        for key, value in obj.items():
            parts.append(str(key))
            parts.append(_extract_json_strings(value))
    elif isinstance(obj, (list, tuple)):
        for item in obj:
            parts.append(_extract_json_strings(item))
    return " ".join(parts)


def strip_html(text: str) -> str:
    attr_values = re.findall(r'(?:alt|title|aria-label|content)\s*=\s*["\']([^"\']*)["\']', text)
    text = re.sub(r"<[^>]+>", " ", text)
    text = " ".join(attr_values) + " " + text
    return text


def strip_markdown(text: str) -> str:
    text = re.sub(r"```[\s\S]*?```", " [CODE_BLOCK] ", text)
    text = re.sub(r"`[^`]+`", " [INLINE_CODE] ", text)
    text = re.sub(r"^#{1,6}\s+", "", text, flags=re.MULTILINE)
    text = re.sub(r"^[>\s]+", "", text, flags=re.MULTILINE)
    text = re.sub(r"\*\*([^*]+)\*\*", r"\1", text)
    text = re.sub(r"\*([^*]+)\*", r"\1", text)
    text = re.sub(r"__([^_]+)__", r"\1", text)
    text = re.sub(r"_([^_]+)_", r"\1", text)
    text = re.sub(r"\[([^\]]+)\]\([^)]+\)", r"\1", text)
    text = re.sub(r"!\[([^\]]*)\]\([^)]+\)", r"\1", text)
    return text
