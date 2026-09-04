from cryptscan.rules.insecure_tls import InsecureTlsRule


def test_insecure_tls_positive(samples_ctx):
    findings = InsecureTlsRule().analyze(samples_ctx)
    vuln = [f for f in findings if "VulnTls" in f.class_name]
    assert vuln
    assert vuln[0].evidence == "SSLv3"


def test_insecure_tls_negative(samples_ctx):
    findings = InsecureTlsRule().analyze(samples_ctx)
    assert not [f for f in findings if "SafeTls" in f.class_name]
