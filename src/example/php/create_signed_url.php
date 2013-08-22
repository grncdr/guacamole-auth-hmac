<?php

if (count($argv) < 4) {
    echo "USAGE: php create_signed_url.php <ID> <PROTOCOL> <HOSTNAME>\n";
    exit(1);
}

require_once(__DIR__ . '/GuacamoleUrlBuilder.php');

list($_, $id, $protocol, $hostname) = $argv;

$extraArgs   = array_slice($argv, 4);
$extraParams = array();

foreach ($extraArgs as $pair) {
    list($key, $value) = explode('=', $pair);
    $extraParams["guac.${key}"] = $value;
}

$urlBuilder = new GuacamoleUrlBuilder("http://localhost:8080/guacamole/client.xhtml", "secret key");
print $urlBuilder->url($id, $protocol, $hostname, $extraParams);
