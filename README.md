# guacamole-auth-hmac

## Description

This project is a plugin for [Guacamole](http://guac-dev.org), an HTML5 based
remote desktop solution supporting VNC/RFB, RDP, and SSH.

This plugin is an _authentication provider_ that enables stateless, on-the-fly
configuration of remote desktop connections that are authorized using a
pre-shared key. It is most appropriate for scenarios where you have an existing
user authentication & authorization mechanism.

## Installation

Currently this plugin requires a [patch to guacamole-client][putconfig-pr]. The
simplest way to get this running is to [install normally][guac-install] and then
replace guacamole.war with a custom build of [my branch][putconfig]. The manual
explains [how to build guacamole-client][guac-build].

After you have a version of guacamole running that implements
`SimpleConnectionDirectory.putConfig` you can build, deploy, and configure this
auth plugin.

[guac-install]: guac-dev.org/doc/gug/installing-guacamole.html
[guac-build]: http://guac-dev.org/doc/gug/installing-guacamole.html#compiling-guacamole-client
[putconfig]: https://github.com/grncdr/guacamole-client/tree/putconfig
[putconfig-pr]: https://github.com/glyptodon/guacamole-client/pull/5

## Deployment & Configuration

Copy `guacamole-auth-hmac.jar` to the location specified by
[`lib-directory`][config-classpath] in `guacamole.properties`. Then set the
`auth-provider` property to `net.sourceforge.guacamole.net.hmac.HmacAuthenticationProvider`.

`guacamole-auth-hmac` adds one new config key to `guacamole.properties`:

 * `secret-key` - This is the key that will be used to verify URL signatures.
    Whatever is generating the signed URLs will need to share this value.


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
 * `guac.host` - The hostname of the remote desktop server to connect to.
 * `guac.port` - The port number to connect to.
 * `guac.username` - (_optional_)
 * `guac.password` - (_optional_)
 * `guac.*` - (_optional_) Any other configuration parameters recognized by
    Guacamole can be by prefixing them with `guac.`.

## Request Signing

Requests must be signed with an HMAC, where the message content is generated
from the request parameters as follows:

 1. The parameters `timestamp`, and `guac.protocol` are concatenated.
 2. For each of `guac.username`, `guac.password`, `guac.host`, and `guac.port`;
    if the parameter was included in the request, append it's unprefixed name
    (e.g. - `guac.username` becomes `username`) followed by it's value.

### Request Signing - Example

Given a request for the following URL:

`client.xhtml?id=example&guac.protocol=rdp&guac.host=myserver.internal&guac.port=3389&timestamp=1377143741000`

The message to be signed will be the concatenation of the following strings:

  - `"1377143741000"`
  - `"rdp"`
  - `"host"`
  - `"myserver.internal"`
  - `"port"`
  - `"3389"`

Assuming a secret key of `"secret"`, a `signature` parameter should be appended
with a value that is the base-64 encoded value of the hash produced by signing
the message `"1377143741000rdphostmyserver.internalport3389"` with the key
`"secret"`, or `"NDk3M2E5ZGFhYjU1MzYxNDhmMDY4ZTJlMzc3YjdhNGIyYzMwODQ1Yw"`. How
this signature is produced is dependent on your programming language/platform,
but with recent versions of PHP it looks like this:

    base64_encode(hash_hmac('sha1', $message, $secret));

An [example PHP implementation][example-php] is included in `src/example/php`.

[example-php]: https://github.com/grncdr/guacamole-auth-hmac/blob/master/src/example/php

## License

MIT License
