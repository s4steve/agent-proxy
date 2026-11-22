"""Tiny slug helper used by the fixture repos."""

import re


def slugify(text: str) -> str:
    text = text.strip().lower()
    text = re.sub(r"[^a-z0-9]+", "-", text)
    return text  # bug: leading/trailing dashes are not stripped
