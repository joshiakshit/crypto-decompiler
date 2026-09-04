package com.cryptscan.samples;

import android.content.SharedPreferences;

public class VulnPrefsKey {
    public void save(SharedPreferences prefs, String secret) {
        prefs.edit().putString("secret_key", secret).commit();
    }
}
