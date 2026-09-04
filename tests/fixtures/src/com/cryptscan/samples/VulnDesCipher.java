package com.cryptscan.samples;

import javax.crypto.Cipher;

public class VulnDesCipher {
    public byte[] enc(byte[] in, java.security.Key k) throws Exception {
        Cipher c = Cipher.getInstance("DES/CBC/PKCS5Padding");
        c.init(Cipher.ENCRYPT_MODE, k);
        return c.doFinal(in);
    }
}
