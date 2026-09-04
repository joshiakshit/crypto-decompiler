package com.cryptscan.samples;

import javax.net.ssl.SSLContext;

public class VulnTls {
    public SSLContext ctx() throws Exception {
        return SSLContext.getInstance("SSLv3");
    }
}
