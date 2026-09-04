from __future__ import annotations

import re

from ..analysis.entropy import is_high_entropy_secret
from ..analysis.xref import (
    app_methods,
    const_offset,
    field_store_strings,
    getinstance_args,
    method_invokes,
)
from ..context import AnalysisContext
from ..findings import Confidence, Finding
from ..findings import Severity as S
from .base import Rule

_SINK = (
    r"L(javax/crypto/spec/SecretKeySpec|javax/crypto/spec/IvParameterSpec"
    r"|javax/crypto/spec/PBEKeySpec|javax/crypto/SecretKeyFactory);"
)
_GETBYTES = r"Ljava/lang/String;->getBytes"
_ALGO_TOKEN = re.compile(
    r"^(AES|DES|DESede|RSA|EC|DSA|RC4|ARCFOUR|Blowfish|BC|AndroidKeyStore"
    r"|UTF-8|US-ASCII|ISO-8859-1|MD5|Hmac.*|SHA-?\d+|.*Padding|PBKDF2.*)$",
    re.I,
)


def _redact(value: str) -> str:
    return f"{value[:4]}...[{len(value)} chars]"


class HardcodedKeysRule(Rule):
    id = "CS001"
    name = "Hardcoded cryptographic key"
    severity = S.CRITICAL
    cwe = "CWE-321"
    remediation = (
        "Load keys from the Android Keystore or derive them at runtime; never embed key bytes."
    )

    def analyze(self, ctx: AnalysisContext) -> list[Finding]:
        findings: list[Finding] = []
        seen: set[tuple[str, str, str]] = set()
        methods = [(ma, ma.get_method()) for ma in app_methods(ctx.dx)]
        crypto_classes = {ma.class_name for ma, em in methods if method_invokes(em, _SINK)}

        # High-entropy literals (base64/hex) referenced beside a key-spec sink.
        for sa in ctx.dx.get_strings():
            value = sa.get_value()
            if "/" in value or not is_high_entropy_secret(value):
                continue
            for cls, meth in sa.get_xref_from():
                em = meth.get_method()
                if em is not None and method_invokes(em, _SINK):
                    self._emit(
                        findings,
                        seen,
                        cls.name,
                        meth.name,
                        str(meth.descriptor),
                        const_offset(meth, value),
                        value,
                    )

        for ma, em in methods:
            # Any literal turned into key bytes; catches human-readable passphrases.
            for off, value in getinstance_args(em, _GETBYTES):
                if method_invokes(em, _SINK):
                    self._emit(
                        findings, seen, ma.class_name, ma.name, str(ma.descriptor), off, value
                    )
            # Literal stored in a field of a class that does key-spec crypto.
            if ma.class_name in crypto_classes:
                for off, value, _field in field_store_strings(em):
                    if len(value) >= 6 and "/" not in value and not _ALGO_TOKEN.match(value):
                        self._emit(
                            findings, seen, ma.class_name, ma.name, str(ma.descriptor), off, value
                        )

        return findings

    def _emit(self, findings, seen, class_name, method, descriptor, offset, value) -> None:
        key = (class_name, method, value)
        if key in seen:
            return
        seen.add(key)
        findings.append(
            self.finding(
                title="Hardcoded cryptographic key or secret",
                class_name=class_name,
                method=method,
                descriptor=descriptor,
                offset=offset,
                evidence=_redact(value),
                confidence=Confidence.HIGH,
            )
        )
