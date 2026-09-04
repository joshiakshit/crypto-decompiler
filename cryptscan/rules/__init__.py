from __future__ import annotations

from collections.abc import Iterable

from .base import Rule
from .broken_algorithms import BrokenAlgorithmsRule
from .cert_validation import CertValidationRule
from .ecb_mode import EcbModeRule
from .hardcoded_keys import HardcodedKeysRule
from .insecure_storage import InsecureStorageRule
from .insecure_tls import InsecureTlsRule
from .weak_random import WeakRandomnessRule

ALL_RULES: list[Rule] = [
    HardcodedKeysRule(),
    EcbModeRule(),
    BrokenAlgorithmsRule(),
    WeakRandomnessRule(),
    InsecureStorageRule(),
    CertValidationRule(),
    InsecureTlsRule(),
]


def get_rules(ids: Iterable[str] | None = None) -> list[Rule]:
    if not ids:
        return list(ALL_RULES)
    wanted = {i.strip().upper() for i in ids}
    return [r for r in ALL_RULES if r.id in wanted]
