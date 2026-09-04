from cryptscan.rules.homegrown_crypto import HomegrownCryptoRule


def test_homegrown_positive(samples_ctx):
    findings = HomegrownCryptoRule().analyze(samples_ctx)
    vuln = [f for f in findings if "VulnXorCrypto" in f.class_name]
    assert vuln


def test_homegrown_negative(samples_ctx):
    findings = HomegrownCryptoRule().analyze(samples_ctx)
    assert not [f for f in findings if "SafeAesWrapper" in f.class_name]
