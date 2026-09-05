package com.cryptscan.samples;

import android.util.Log;
import java.security.MessageDigest;
import javax.crypto.Cipher;

public class DecoyWeakAlgoLog {
    public byte[] hash(byte[] in) throws Exception {
        Log.d("MD5", "legacy tag");                 // const "MD5", never reaches getInstance
        return MessageDigest.getInstance("SHA-256").digest(in);
    }

    public Cipher cipher() throws Exception {
        Log.d("DES", "legacy tag");                 // const "DES", never reaches getInstance
        return Cipher.getInstance("AES/GCM/NoPadding");
    }
}
