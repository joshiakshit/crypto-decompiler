package com.cryptscan.samples;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public class VulnPassphraseKey {
    public SecretKey key() {
        return new SecretKeySpec("correct horse battery".getBytes(), "AES");
    }
}
