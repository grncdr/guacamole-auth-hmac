package org.glyptodon.guacamole.net.hmac;

/**
 * Created with IntelliJ IDEA.
 * User: stephen
 * Date: 2013-07-11
 * Time: 10:37 AM
 * To change this template use File | Settings | File Templates.
 */
public class DefaultTimeProvider implements TimeProviderInterface {
    public long currentTimeMillis() {
        return System.currentTimeMillis();
    }
}
