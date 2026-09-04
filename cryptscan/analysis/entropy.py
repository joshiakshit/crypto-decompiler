from __future__ import annotations

import math
import re

_BASE64 = re.compile(r"^[A-Za-z0-9+/]+={0,2}$")
_HEX = re.compile(r"^[0-9a-fA-F]+$")


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    n = len(s)
    counts: dict[str, int] = {}
    for ch in s:
        counts[ch] = counts.get(ch, 0) + 1
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def looks_base64(s: str) -> bool:
    return len(s) >= 16 and len(s) % 4 == 0 and bool(_BASE64.match(s))


def looks_hex(s: str) -> bool:
    return len(s) >= 16 and len(s) % 2 == 0 and bool(_HEX.match(s))


def is_high_entropy_secret(s: str, min_entropy: float = 3.5) -> bool:
    if len(s) < 16 or " " in s:
        return False
    if not (looks_base64(s) or looks_hex(s)):
        return False
    return shannon_entropy(s) >= min_entropy
