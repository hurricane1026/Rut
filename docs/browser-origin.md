# Browser mutation origin guard

The example `examples/browser-origin-auth.rut` checks a singleton `Origin`
header before browser mutations. Configure `BROWSER_ORIGIN` as a canonical
serialized HTTP or HTTPS origin; malformed configuration returns 503. Missing,
repeated, opaque, or nonmatching request origins return 403. Origin checking
complements authentication and authorization.

For two explicitly trusted frontends, `requireEitherOrigin(first, second)`
validates both deployment-owned origins, which must be distinct, and allows
only a single header matching either exactly. The `/shared/write` example uses
`BROWSER_ORIGIN` and `BROWSER_SECOND_ORIGIN`. Invalid or equal configured
origins return 503, even when the request matches the other origin.

## Clearing the host-bound session cookie

Serve [browser-session-clear.rut](../examples/browser-session-clear.rut) over
HTTPS. Set `BROWSER_ORIGIN` to the deployment's exact HTTPS origin and
`BROWSER_FETCH_SITE` to `same-origin`. The POST route requires both a matching
singleton Origin and a singleton `Sec-Fetch-Site: same-origin`.

```sh
BROWSER_ORIGIN=https://localhost:8443 BROWSER_FETCH_SITE=same-origin \
  rut 8443 examples/browser-session-clear.rut --tls-cert cert.pem --tls-key key.pem
```

The fixed clear response is 204 with `Cache-Control: no-store` and one
`Set-Cookie` for `__Host-rut_session` with `Path=/`, `Max-Age=0`, `Secure`,
`HttpOnly` and `SameSite=Strict`. Use the same name and path at issuance. In a
logout handler, verify the session and acknowledge server-side revocation
before returning this response. The example exercises the browser response
and its request guards.
