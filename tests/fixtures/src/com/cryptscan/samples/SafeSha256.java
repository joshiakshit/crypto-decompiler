package com.cryptscan.samples;

import java.security.MessageDigest;

public class SafeSha256 {
    public byte[] hash(byte[] in) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        return md.digest(in);
    }
}
