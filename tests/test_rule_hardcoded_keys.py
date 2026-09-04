from cryptscan.findings import Severity
from cryptscan.rules.hardcoded_keys import HardcodedKeysRule


def test_hardcoded_key_positive(samples_ctx):
    findings = HardcodedKeysRule().analyze(samples_ctx)
    vuln = [f for f in findings if "VulnHardcodedKey" in f.class_name]
    assert vuln
    assert vuln[0].severity is Severity.CRITICAL
    assert "7a1f" in vuln[0].evidence


def test_hardcoded_passphrase_positive(samples_ctx):
    findings = HardcodedKeysRule().analyze(samples_ctx)
    assert [f for f in findings if "VulnPassphraseKey" in f.class_name]


def test_hardcoded_field_key_positive(samples_ctx):
    findings = HardcodedKeysRule().analyze(samples_ctx)
    assert [f for f in findings if "VulnFieldKey" in f.class_name]


def test_hardcoded_key_negative(samples_ctx):
    findings = HardcodedKeysRule().analyze(samples_ctx)
    assert not [f for f in findings if "SafeKeystore" in f.class_name]
