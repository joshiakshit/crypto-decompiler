from __future__ import annotations

import hashlib
from pathlib import Path

from loguru import logger

from .context import AnalysisContext

logger.disable("androguard")


def _sha256(p: Path) -> str:
    return hashlib.sha256(p.read_bytes()).hexdigest()


def load(path: str | Path) -> AnalysisContext:
    p = Path(path)
    if p.suffix.lower() == ".dex":
        return _load_dex(p)
    return _load_apk(p)


def _load_apk(p: Path) -> AnalysisContext:
    from androguard.misc import AnalyzeAPK

    apk, _, dx = AnalyzeAPK(str(p))
    target = {
        "path": str(p),
        "sha256": _sha256(p),
        "package": apk.get_package(),
        "min_sdk": apk.get_min_sdk_version(),
        "target_sdk": apk.get_target_sdk_version(),
    }
    return AnalysisContext(dx=dx, apk=apk, target=target)


def _load_dex(p: Path) -> AnalysisContext:
    from androguard.misc import AnalyzeDex

    _, _, dx = AnalyzeDex(str(p))
    target = {
        "path": str(p),
        "sha256": _sha256(p),
        "package": None,
        "min_sdk": None,
        "target_sdk": None,
    }
    return AnalysisContext(dx=dx, apk=None, target=target)
