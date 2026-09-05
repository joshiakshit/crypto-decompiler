package com.cryptscan.samples;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public class VulnCharsetKey {
    public SecretKey key() throws Exception {
        return new SecretKeySpec("charset passphrase here".getBytes("UTF-8"), "AES");
    }
}
