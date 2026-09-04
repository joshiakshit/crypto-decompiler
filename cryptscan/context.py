from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass
class AnalysisContext:
    dx: Any
    apk: Any | None
    target: dict
