package com.cryptscan.samples;

import javax.crypto.Cipher;

public class SafeAesWrapper {
    public byte[] encrypt(byte[] data, java.security.Key k) throws Exception {
        Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
        c.init(Cipher.ENCRYPT_MODE, k);
        return c.doFinal(data);
    }
}
