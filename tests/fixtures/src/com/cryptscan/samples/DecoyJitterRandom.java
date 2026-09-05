package com.cryptscan.samples;

import java.security.SecureRandom;
import java.util.Random;
import javax.crypto.spec.IvParameterSpec;

public class DecoyJitterRandom {
    public IvParameterSpec iv() {
        byte[] iv = new byte[16];
        new SecureRandom().nextBytes(iv);           // IV bytes come from SecureRandom
        int jitter = new Random().nextInt(50);      // java.util.Random used only for backoff
        return new IvParameterSpec(iv);             // sink arg is the secure iv, not jitter
    }
}
