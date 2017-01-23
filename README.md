# guacamole-auth-hmac [![Build Status](https://travis-ci.org/grncdr/guacamole-auth-hmac.png?branch=master)](https://travis-ci.org/grncdr/guacamole-auth-hmac)

## WARNING! Unmaintained!

This was written for a client, and as I have no personal use for it, I'm not maintaining it anymore.

## Description

This project is a plugin for [Guacamole](http://guac-dev.org), an HTML5 based
remote desktop solution supporting VNC/RFB, RDP, and SSH.

This plugin is an _authentication provider_ that enables stateless, on-the-fly
configuration of remote desktop connections that are authorized using a
pre-shared key. It is most appropriate for scenarios where you have an existing
user authentication & authorization mechanism.

## Building

guacamole-auth-hmac uses Maven for managing builds. After installing Maven you can build a
suitable jar for deployment with `mvn package`.

The resulting jar file will be placed in `target/guacamole-auth-hmac-<version>.jar`.

## Deployment & Configuration

**Warning** This plugin relies on API's introduced in Guacamole 0.8.3, so you must be running
at least that version before using this plugin.

Copy `guacamole-auth-hmac.jar` to the location specified by
[`lib-directory`][config-classpath] in `guacamole.properties`. Then set the
`auth-provider` property to `com.stephensugden.guacamole.net.hmac.HmacAuthenticationProvider`.

`guacamole-auth-hmac` adds two new config keys to `guacamole.properties`:

 * `secret-key` - The key that will be used to verify URL signatures.
    Whatever is generating the signed URLs will need to share this value.
 * `timestamp-age-limit` - A numeric value (in milliseconds) that determines how long
    a signed request should be valid for.


[config-classpath]: http://guac-dev.org/doc/gug/configuring-guacamole.html#idp380240

## Usage

To generate a signed URL for usage with this plugin, simply use the path to
Guacamole's built-in `/client.xhtml` as a base, and append the following query
parameters:

 * `id`  - A connection ID that must be unique per user session.
 * `timestamp` - A unix timestamp in milliseconds. (E.G. `time() * 1000` in PHP).
   This is used to prevent replay attacks.
 * `signature` - The [request signature][#request-signing]
 * `guac.protocol` - One of `vnc`, `rdp`, or `ssh`.
 * `guac.hostname` - The hostname of the remote desktop server to connect to.
 * `guac.port` - The port number to connect to.
 * `guac.username` - (_optional_)
 * `guac.password` - (_optional_)
 * `guac.*` - (_optional_) Any other configuration parameters recognized by
    Guacamole can be by prefixing them with `guac.`.

## Request Signing

Requests must be signed with an HMAC, where the message content is generated
from the request parameters as follows:

 1. The parameters `timestamp`, and `guac.protocol` are concatenated.
 2. For each of `guac.username`, `guac.password`, `guac.hostname`, and `guac.port`;
    if the parameter was included in the request, append it's unprefixed name
    (e.g. - `guac.username` becomes `username`) followed by it's value.

### Request Signing - Example

Given a request for the following URL:

`client.xhtml?id=example&guac.protocol=rdp&guac.hostname=myserver.internal&guac.port=3389&timestamp=1377143741000`

The message to be signed will be the concatenation of the following strings:

  - `"1377143741000"`
  - `"rdp"`
  - `"hostname"`
  - `"myserver.internal"`
  - `"port"`
  - `"3389"`

Assuming a secret key of `"secret"`, a `signature` parameter should be appended
with a value that is the base-64 encoded value of the hash produced by signing
the message `"1377143741000rdphostnamemyserver.internalport3389"` with the key
`"secret"`, or `"Iost5ouayLzpKLgx607kY1QUVwY="`. How
this signature is produced is dependent on your programming language/platform,
but with recent versions of PHP it looks like this:

    base64_encode(hash_hmac('sha1', $message, $secret));

An [example PHP implementation][example-php] is included in `src/example/php`.

[example-php]: https://github.com/grncdr/guacamole-auth-hmac/blob/master/src/example/php

## License

MIT License
