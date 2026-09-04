from cryptscan.rules.insecure_storage import InsecureStorageRule


def test_insecure_storage_positive(samples_ctx):
    findings = InsecureStorageRule().analyze(samples_ctx)
    vuln = [f for f in findings if "VulnPrefsKey" in f.class_name]
    assert vuln
    assert vuln[0].evidence == "secret_key"


def test_insecure_storage_negative(samples_ctx):
    findings = InsecureStorageRule().analyze(samples_ctx)
    assert not [f for f in findings if "SafePrefs" in f.class_name]
