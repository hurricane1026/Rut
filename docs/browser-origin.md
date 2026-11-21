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
