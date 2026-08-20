# nginx converter architecture

## Goal

The converter is a compatibility frontend, not a directive-to-syntax
translator. A configuration is accepted only when every directive that affects
the supported behavior has a validated nginx semantic representation and an
equivalent RUT lowering. Unsupported input is a diagnostic, never a no-op.

The first behavioral milestone is the following server fragment:

```nginx
server {
    listen 8080;

    location / {
        proxy_pass http://127.0.0.1:9000;
    }
}
```

The fragment form is the initial converter input. A differential test may wrap
it in the required `events {}` and `http {}` contexts before giving it to a real
nginx process. Support for arbitrary full nginx files is not implied.

## Proposed pipeline

```text
nginx source
  -> nginx lexer/parser (syntax and source spans)
  -> nginx semantic model
  -> capability validation
  -> RUT source/config emission
  -> existing RUT lexer -> AST -> HIR -> MIR -> RIR -> JIT/runtime
```

The nginx frontend should live in a separate `rut/nginx` library and must not be
added to the RUT parser. The semantic model owns nginx concepts such as
listeners, server selection, location selection, proxy URI policy, and inherited
header policy. Lowering happens only after the whole accepted input has passed
capability validation.

The first implementation should emit auditable RUT source and retain source
spans for diagnostics. It must not construct `RouteConfig` directly or bypass
the existing compiler. If a semantic model value cannot be represented in RUT
source/config, the feature is `BLOCKED_BY_RUT`; direct HIR construction is not a
fallback for hiding a language/runtime gap.

## Initial semantic model boundary

The first parser increment represents, but does not yet lower:

- exactly one server fragment;
- one explicit IPv4 wildcard HTTP listen port;
- one ordinary prefix location whose path is `/`;
- one literal `http://<IPv4>:<port>` `proxy_pass` with no URI suffix.

All unknown directives, duplicate directives, modifiers, variables, named
upstreams, URI suffixes, and additional contexts must produce a source-located
unsupported or invalid diagnostic. Whitespace and `#` comments are syntax, not
directives, and may be accepted.

## Semantics that the first end-to-end test must preserve

- `/` is an all-method catch-all location for ordinary origin-form requests.
- Routing uses nginx's normalized URI, while a `proxy_pass` without a URI part
  forwards the original request target, including query text and encoding.
- The request method and body are preserved.
- Listener address/port are configuration semantics and cannot be dropped.
- Proxy request version, Host, hop-by-hop/framing headers, response header
  filtering, and gateway failures are observable behavior.

The nginx version used by every differential result must be recorded. In
particular, the default upstream HTTP version changes at nginx 1.29.7, so a
result from one version is not evidence for every nginx version.

## Test layers

1. Parser tests: model fields, spans, and fail-closed diagnostics.
2. Golden tests: nginx input to deterministic RUT source/config.
3. Differential tests: real nginx and RUT receive the same raw requests and use
   recording upstreams. Compare client status/headers/body and upstream
   method/version/request-target/headers/body.

Differential process tests belong in a dedicated CTest target marked serial.
Local absence of nginx is an explicit skip/unsupported result; CI compatibility
evidence must use a pinned nginx build and cannot treat that skip as a pass.

## First three increments

1. Add the minimal nginx lexer/parser and semantic model, with strict rejection
   of everything outside the initial boundary. No RUT emission.
2. Use the shipped method-omitted RUT route form for all-method locations;
   the source listener dependency is resolved, while proxy policy dependencies
   still need resolution.
3. Add capability validation and deterministic RUT lowering for the minimal
   model after listener and proxy policy dependencies are explicitly resolved;
   then add the first serialized differential smoke case.

## Known capability dependencies

- #250 (closed): downstream listener capability is available for one source
  wildcard listener; converter lowering and nginx differential evidence remain
  pending in #254.
- #252: upstream HTTP request policy for `forward`.
- #253: proxied response header policy.
