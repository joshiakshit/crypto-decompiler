from __future__ import annotations

from collections.abc import Iterable

from .base import Rule
from .ecb_mode import EcbModeRule

ALL_RULES: list[Rule] = [
    EcbModeRule(),
]


def get_rules(ids: Iterable[str] | None = None) -> list[Rule]:
    if not ids:
        return list(ALL_RULES)
    wanted = {i.strip().upper() for i in ids}
    return [r for r in ALL_RULES if r.id in wanted]
