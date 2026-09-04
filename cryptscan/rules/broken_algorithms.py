from __future__ import annotations

from ..analysis.xref import method_invokes, strings_matching
from ..context import AnalysisContext
from ..findings import Confidence, Finding
from ..findings import Severity as S
from .base import Rule

_HASH = r"^(MD5|SHA-1|SHA1)$"
_CIPHER = r"^(DESede|DES|RC4|ARCFOUR|RC2|Blowfish)(/.*)?$"
_MESSAGE_DIGEST = r"L(java/security/MessageDigest|javax/crypto/Mac);->getInstance"
_CIPHER_GET = r"Ljavax/crypto/Cipher;->getInstance"


class BrokenAlgorithmsRule(Rule):
    id = "CS003"
    name = "Broken or deprecated algorithm"
    severity = S.HIGH
    cwe = "CWE-327"
    remediation = "Use SHA-256+ for hashing and AES-GCM for encryption. Avoid MD5, SHA-1, DES, RC4."

    def analyze(self, ctx: AnalysisContext) -> list[Finding]:
        findings: list[Finding] = []
        findings += self._scan(ctx, _HASH, _MESSAGE_DIGEST, "Weak hash algorithm", S.MEDIUM)
        findings += self._scan(ctx, _CIPHER, _CIPHER_GET, "Broken cipher algorithm", S.HIGH)
        return findings

    def _scan(self, ctx, value_re, api_re, title, severity) -> list[Finding]:
        out: list[Finding] = []
        for value, refs in strings_matching(ctx.dx, value_re):
            for cls_name, meth, off in refs:
                em = meth.get_method()
                if em is None or not method_invokes(em, api_re):
                    continue
                out.append(
                    self.finding(
                        title=f"{title} ({value})",
                        class_name=cls_name,
                        method=meth.name,
                        descriptor=str(meth.descriptor),
                        offset=off,
                        evidence=value,
                        severity=severity,
                        confidence=Confidence.HIGH,
                    )
                )
        return out
