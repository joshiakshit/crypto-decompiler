from __future__ import annotations

from ..analysis.xref import app_methods, weak_random_material
from ..context import AnalysisContext
from ..findings import Confidence, Finding
from ..findings import Severity as S
from .base import Rule

_WEAK = r"Ljava/util/Random;->|Ljava/lang/Math;->random"
_MATERIAL = r"Ljavax/crypto/spec/(SecretKeySpec|IvParameterSpec);-><init>"


class WeakRandomnessRule(Rule):
    id = "CS004"
    name = "Weak randomness feeding crypto"
    severity = S.HIGH
    cwe = "CWE-330"
    remediation = "Use java.security.SecureRandom for keys, IVs, nonces and salts."

    def analyze(self, ctx: AnalysisContext) -> list[Finding]:
        findings: list[Finding] = []
        for ma in app_methods(ctx.dx):
            em = ma.get_method()
            for off, target in weak_random_material(em, _WEAK, _MATERIAL):
                findings.append(
                    self.finding(
                        title="Insecure java.util.Random used for crypto material",
                        class_name=ma.class_name,
                        method=ma.name,
                        descriptor=str(ma.descriptor),
                        offset=off,
                        evidence=target,
                        confidence=Confidence.MEDIUM,
                    )
                )
                break
        return findings
