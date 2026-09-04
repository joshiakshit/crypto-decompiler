package com.cryptscan.samples;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public class VulnFieldKey {
    private String key = "hunter2 default admin key";

    public SecretKey secret() {
        return new SecretKeySpec(key.getBytes(), "AES");
    }
}
