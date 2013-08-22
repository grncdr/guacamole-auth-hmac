<?php

/**
 * Usage example:
 *
 *     $urlBuilder = new GuacamoleUrlBuilder("my secret key", "http://myguacamoleserver.internal/client.xhtml");
 *     $url = $urlBuilder->url("myserver", "vnc", "myvncserver.internal");
 */
class GuacamoleUrlBuilder {
    private static $signedParams = array(
        'guac.username',
        'guac.password',
        'guac.hostname',
        'guac.port'
    );

    /** @var string */
    protected $clientUrl;

    /** @var string */
    protected $secretKey;

    public function __construct($secretKey, $clientUrl) {
        $this->clientUrl = $clientUrl;
        $this->secretKey = $secretKey;
    }

    public function url(string $connectionId, string $protocol, string $hostname, $extraParams = array()) {
        $timestamp = time() * 1000;

        // Array of query parameters to pass to guacamole
        $qp = array(
            'id'            => $connectionId,
            'timestamp'     => $timestamp,
            'guac.hostname' => $hostname,
            'guac.protocol' => $protocol
        );

        // Copy any extra guacamole key value params into the query string
        foreach ($extraParams as $key => $value) {
            if (strpos($key, 'guac.') === 0) {
                $qp[$key]  = $value;
            }
        }

        // Add default port
        if (!array_key_exists('guac.port', $qp)) {
            if ($protocol == 'rdp') {
                $qp['guac.port'] = '3389';
            }
            else if ($protocol == 'vnc') {
                $qp['guac.port'] = '5900';
            }
            else if ($protocol == 'ssh') {
                $qp['guac.port'] = '22';
            }
        }

        // It's important that the message string used to generate the signature
        // is built in the correct order
        $message = "$timestamp$protocol";

        foreach (self::$signedParams as $name) {
            $value = @$qp[$name];
            if (is_null($value)) {
                continue;
            }
            $message .= substr($name, 5);
            $message .= $value;
        }

        return $this->clientUrl . '?'
            . str_replace('+', '%20', http_build_query($qp))
            . '&signature='
            . base64_encode(hash_hmac('sha1', $message, $this->secretKey, 1));
    }
}


