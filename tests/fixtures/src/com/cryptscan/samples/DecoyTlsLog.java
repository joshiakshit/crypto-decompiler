package com.cryptscan.samples;

import android.util.Log;
import javax.net.ssl.SSLContext;

public class DecoyTlsLog {
    public SSLContext ctx() throws Exception {
        Log.w("SSLv3", "disabled by policy");       // const "SSLv3", never reaches getInstance
        return SSLContext.getInstance("TLSv1.3");
    }
}
