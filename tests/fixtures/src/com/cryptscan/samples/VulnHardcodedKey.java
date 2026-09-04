package com.cryptscan.samples;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

public class VulnHardcodedKey {
    private static final String KEY = "7a1f8bc39d5e024f6a8c1b3d5e7f9a2c";

    public byte[] enc(byte[] in) throws Exception {
        SecretKeySpec ks = new SecretKeySpec(KEY.getBytes("UTF-8"), "AES");
        Cipher c = Cipher.getInstance("AES/CBC/PKCS5Padding");
        c.init(Cipher.ENCRYPT_MODE, ks);
        return c.doFinal(in);
    }
}
