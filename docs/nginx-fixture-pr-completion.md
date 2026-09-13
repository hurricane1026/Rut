# IPv4 fixture draft completion

The user selected completion and merge of #374, #376, then #269 on
2026-09-13. This supersedes the earlier handoff instruction to keep #269 draft.

## #374: replace the preservation spike with accepted infrastructure

The original `3b00c6af` spike was rejected. Its two-file implementation is
retired when merging current converter integration into the original branch;
the resulting source and tests exactly match accepted integration `a283731e`.
No rejected socket, process, or cleanup implementation is reintroduced.

The split implementation already landed through authenticated worker protocol
`01b92ba5`/`fda50395`, topology `db6153f0`, privileged broker #375,
canonical collision/release #394 and assigned-address generated nginx/RUT
differential #424. #424 records accepted head `af5c04f9`, standard CI
`33668450721`, required privileged run `33670045263`, direct and CTest
differentials, and `residual-count=0 audit-error=0`. This historical result
is not a fresh run of the current branch.

The remaining CI defect was the privileged workflow being restricted to the
old #375 branch. It now executes for same-repository PRs, main pushes and
manual dispatch, retaining exact-head checkout, required preflight, direct
and CTest topology/broker/differential checks, and the final residue audit.
Fresh current-head CI is required before merging #374.

## #376: live wildcard handoff acceptance remains pending

The accepted canonical collision/release fixture uses an exact-address source.
Closing #377 does not by itself prove #376 wildcard dual-address traffic or
isolated destructive runtime mutations. The old rejected implementation must
not be merged unchanged. Review and implementation of these remaining gates
precede #376 and #269 completion.
