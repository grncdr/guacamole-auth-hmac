package com.aiden0z.guacamole.net.hmac;

public class DefaultTimeProvideService implements TimeProvideService {

    public long currentTimeMillis() {

        return System.currentTimeMillis();
    }
}
