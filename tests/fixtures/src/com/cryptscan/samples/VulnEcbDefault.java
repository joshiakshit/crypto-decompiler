package com.cryptscan.samples;

import javax.crypto.Cipher;

public class VulnEcbDefault {
    public byte[] enc(byte[] in, java.security.Key k) throws Exception {
        Cipher c = Cipher.getInstance("AES");
        c.init(Cipher.ENCRYPT_MODE, k);
        return c.doFinal(in);
    }
}
