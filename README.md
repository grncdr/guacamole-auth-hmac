# guacamole-auth-hmac


## Description

This project is a plugin for [Guacamole](http://guac-dev.org), an HTML5 based
remote desktop solution supporting VNC/RFB, RDP, and SSH.

This plugin is an [authentication provider](http://guacamole.incubator.apache.org/doc/gug/custom-auth.html) that enables stateless, on-the-fly
configuration of remote desktop connections that are authorized using a
pre-shared key. It is most appropriate for scenarios where you have an existing
user authentication & authorization mechanism.


## Deployment & Configuration

* [deploy guacamole extension](http://guacamole.incubator.apache.org/doc/gug/configuring-guacamole.html)
* [custom authentication](http://guacamole.incubator.apache.org/doc/gug/custom-auth.html)

`guacamole-auth-hmac` adds two new config keys to `guacamole.properties`:

 * `secret-key` - The key that will be used to verify URL signatures.
    Whatever is generating the signed URLs will need to share this value.
 * `timestamp-age-limit` - A numeric value (in milliseconds) that determines how long
    a signed request should be valid for.

## Usage

#### First

Use flowing parameters to get auth token from the rest api `/api/token` of guacamole web server.

 * `GUAC_ID`  - A connection ID that must be unique per user session;
 * `GUAC_TYPE`  - connection type, 'c' or 'g';
 * `timestamp` - A unix timestamp in milliseconds, this is used to prevent replay attacks;
 * `signature` - The signature string;
 * `guac.protocol` - One of `vnc`, `rdp`, or `ssh`;
 * `guac.hostname` - The hostname of the remote desktop server to connect to;
 * `guac.port` - The port number to connect to;
 * `guac.username` - (_optional_);
 * `guac.password` - (_optional_);
 * `guac.*` - (_optional_) Any other configuration parameters recognized by
    Guacamole can be by prefixing them with `guac.`;

The json response from `/api/token` like:

```
{
  "authToken": "167b2301e6d274be94b94e885cdab5c98b59b6e5a88872620e69391947f39efa",
  "username": "e4695c00-557c-42bb-b209-8ed522a35d8e",
  "dataSource":"hmac",
  "availableDataSources":["hmac"]
}

```

#### Second

Use flowing parameters to initialize the websocket connection to guacamole tunnel endpoint `/websocket-tunnel`.

 * `GUAC_ID` - A connection ID specified in first step;
 * `GUAC_TYPE` - Connection type specified in first step;
 * `GUAC_DATA_SOURCE` - The authentication provider identifier, always is 'hmac';
 * `token` -  Auth token in `/api/token` guacamole rest api response json;


## How to signing ?
Requests must be signed with an HMAC, where the message content is generated from the request parameters as follows:

* 1. The value of parameters `timestamp`, `guac.protocol` are concatenated;
* 2. For each of `guac.username`, `guac.password`, `guac.hostname`, and `guac.port` (must in this order),  if the parameter was included in the request, append it's unprefixed name (e.g. - guac.username becomes username) followed by it's value.



## License

MIT License
