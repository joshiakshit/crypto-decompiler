package com.cryptscan.samples;

import javax.crypto.Cipher;

public class SafeGcm {
    public byte[] enc(byte[] in, java.security.Key k) throws Exception {
        Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
        c.init(Cipher.ENCRYPT_MODE, k);
        return c.doFinal(in);
    }
}
