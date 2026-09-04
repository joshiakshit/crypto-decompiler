package com.cryptscan.samples;

import javax.crypto.Cipher;

public class VulnEcb {
    public byte[] enc(byte[] in, java.security.Key k) throws Exception {
        Cipher c = Cipher.getInstance("AES/ECB/PKCS5Padding");
        c.init(Cipher.ENCRYPT_MODE, k);
        return c.doFinal(in);
    }
}
