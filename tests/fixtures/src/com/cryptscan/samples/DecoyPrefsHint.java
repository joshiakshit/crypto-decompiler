package com.cryptscan.samples;

import android.content.SharedPreferences;
import android.util.Log;

public class DecoyPrefsHint {
    public void save(SharedPreferences prefs, String value) {
        Log.d("hint", "password");                  // secret-named const, not a putString arg
        prefs.edit().putString("theme", value).commit();
    }
}
