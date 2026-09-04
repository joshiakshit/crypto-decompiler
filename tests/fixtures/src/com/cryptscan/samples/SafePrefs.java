package com.cryptscan.samples;

import android.content.SharedPreferences;

public class SafePrefs {
    public void save(SharedPreferences prefs, String name) {
        prefs.edit().putString("display_name", name).commit();
    }
}
