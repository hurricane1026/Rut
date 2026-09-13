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
#374 head `8d8fc9ce` passed standard and pinned-nginx CI `34740047967`
(164/164 nginx tests, zero skips, 654.26s) and privileged CI `34740047963`
(direct/CTest topology, broker and generated differential; final
`residual-count=0 audit-error=0`). It merged as `c966c023`.
The ready-for-review event started a redundant privileged run of the same
already-tested head; that duplicate was canceled after merge.

## #376: isolated live wildcard handoff candidate

Source `04a5b1a8` replaces the rejected monolithic transaction with authenticated
version/mode/Target-start and monotonically ordered phase/decision frames.
The parent independently inspects live exact/wildcard processes, socket inodes,
source and collision-log files, guard custody, port absence, FD count, child
absence and temporary-file removal before authorizing irreversible transitions.

Six fresh mutation sessions actually omit collision execution, close the guard
early, launch exact listeners on each assigned address, replace a captured
wildcard listener with a fresh child/inode, or terminate the retry before real
requests. The shared live validator must reject at the designated phase, and
an additional observed-cause check rejects unrelated failures. After every
complete mutation cleanup, a fresh canonical session proves held collision,
guard-last release, wildcard dual-address exact 65-byte 204/EOF, stable custody
and final zero residue. Existing exact/canonical/generated scenarios remain.

Different-worker review APPROVE followed the mutation-to-canonical recovery
correction. Primary-agent implementation fallback supplied the live protocol
and cause checks after an incomplete worker draft; the earlier draft remains
`/tmp/rut376-live-target.cc`, not accepted code. Local single-TU Clang Release
build/link and both protocol/wait-strategy self-checks pass. The local ordinary
run returns prerequisite skip 77 because passwordless sudo is unavailable;
this is not live acceptance. Fresh full and required privileged CI must pass
before #376 or #269 merge. No converter/runtime or compatibility expansion.
