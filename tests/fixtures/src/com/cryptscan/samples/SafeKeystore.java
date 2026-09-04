package com.cryptscan.samples;

import java.security.Key;
import java.security.KeyStore;

public class SafeKeystore {
    public Key load(String alias) throws Exception {
        KeyStore ks = KeyStore.getInstance("AndroidKeyStore");
        ks.load(null);
        return ks.getKey(alias, null);
    }
}
