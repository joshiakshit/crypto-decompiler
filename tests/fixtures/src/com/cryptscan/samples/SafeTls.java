package com.cryptscan.samples;

import javax.net.ssl.SSLContext;

public class SafeTls {
    public SSLContext ctx() throws Exception {
        return SSLContext.getInstance("TLSv1.3");
    }
}
