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
   then add the first serialized differential smoke case. This increment is
   complete for the bounded header-only H1.1 GET/final-Content-Length vector;
   it does not complete the broader minimal-fragment behavior claim.

## Known capability dependencies

- #250 (closed): downstream listener capability is available for one source
  wildcard listener; bounded converter lowering and nginx differential evidence
  are complete, while broader #254 acceptance remains pending.
- #252: a bounded H1.1 upstream request policy now stages one fixed-CL request
  within the existing 16 KiB composite slice before connect; larger bodies and
  broader request behavior remain `PARTIAL`.
- #253: a bounded final-H1.1 exact-Content-Length response policy is available;
  fixed-CL request-body admission, one upstream `Connection` field, and
  request-derived downstream keep-alive/close behavior are now covered, while
  broader response behavior remains `PARTIAL`.
- #256 (closed): the converter emits an explicit bounded forward-failure policy.
  For single-IPv4 H1 connect failure it matches nginx 1.29.7's 157-byte CRLF
  error body, synthesized headers, request-derived connection, and body wait.

## First process-loop evidence

Using pinned nginx 1.29.7 at digest
`sha256:1854da86e82d5dfb49a8f3d78b099adcc7e36608b207146ed95cd47937938a40`,
the same server fragment was included by nginx and parsed/lowered by the
converter API. A header-only GET/query request with duplicate ordinary headers
produced byte-identical recorded upstream requests. A split four-byte binary
fixed-Content-Length POST also delayed backend accept until the full body was
available and produced byte-identical upstream bytes. Both GET and POST
downstream responses matched the pinned expected response after normalizing
only the generated Date.

This is a real nginx -> converter -> RUT -> runtime loop, not general
`proxy_pass` support. Success GET/POST and bounded unavailable-upstream vectors
now pass; #254 remains open only while its explicit percent-encoded target
acceptance vector is audited.
