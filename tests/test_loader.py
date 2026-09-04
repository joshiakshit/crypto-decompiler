def test_load_apk_metadata(samples_apk_ctx):
    ctx = samples_apk_ctx
    assert ctx.apk is not None
    assert ctx.target["package"] == "com.cryptscan.samples"
    assert len(ctx.target["sha256"]) == 64


def test_load_dex_has_analysis(samples_ctx):
    classes = {c.name for c in samples_ctx.dx.get_classes()}
    assert "Lcom/cryptscan/samples/VulnEcb;" in classes
    assert samples_ctx.apk is None
