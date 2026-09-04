package com.cryptscan.samples;

import java.security.MessageDigest;

public class VulnBrokenHash {
    public byte[] hash(byte[] password) throws Exception {
        MessageDigest md = MessageDigest.getInstance("MD5");
        return md.digest(password);
    }
}
