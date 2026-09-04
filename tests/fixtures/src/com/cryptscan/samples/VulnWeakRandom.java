package com.cryptscan.samples;

import java.util.Random;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;

public class VulnWeakRandom {
    public byte[] enc(byte[] in, java.security.Key k) throws Exception {
        byte[] iv = new byte[16];
        new Random().nextBytes(iv);
        Cipher c = Cipher.getInstance("AES/CBC/PKCS5Padding");
        c.init(Cipher.ENCRYPT_MODE, k, new IvParameterSpec(iv));
        return c.doFinal(in);
    }
}
