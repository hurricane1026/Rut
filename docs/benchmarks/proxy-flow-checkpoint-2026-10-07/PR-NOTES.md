# io_uring PR scope

This draft ports the preserved experimental optimization stack onto current main.
It includes prerequisites for bounded response release, direct-recv ownership,
settled bounded GET origin reuse, per-batch owner indexing, response-owned node
recycling, published-prefix/header coalescing and private dirty body-cache loans.
The opt-in whole-node vector, close-only direct-send and adaptive cache experiments
are retained. Failed SEND_ZC and payload-alignment code has been removed; universal
immediate sends on persistent connections are not permitted.

The original checkpoint is b4d350aa, with historical data preserved here. That
frozen binary is not the newly rebased draft build. The native-streaming comparison
had two timeouts in four c128 keep-alive runs (9 and 5); this remains unresolved.
The original converter-bounded acceptance had no errors. No blanket performance
claim or readiness-to-merge assertion is made for the rebased draft.

Use RUT_STUDY_BODY_POOL_REUSE=1, RUT_STUDY_SELECTIVE_VECTOR=1,
RUT_STUDY_DIRECT_BODY_SEND=1 and RUT_STUDY_ADAPTIVE_CACHE=1 to reproduce the
selected experiments. Direct sends additionally require exact Connection: close.
RUT_STUDY_BODY_POOL_LOG=1 enables counters. Ordinary/public pool loans remain
zero-filled; private body-cache behavior is enabled explicitly in its unit tests.

Validation of the rebased draft (main fbb37d3c): Release/O2, JIT disabled;
network 1579 tests / 350694 checks passed both with default flags and with selected
experiments enabled; arena 76 tests / 1876984 checks passed in both modes;
benchmark tooling 35 tests passed. Only changed C++ ranges were formatted.
The integration test source was ported with its bounded-body prerequisites but
JIT-enabled integration, new PR-branch performance, sanitizer and full tidy
validation have not been rerun. This remains a draft until those and the reported
native-streaming timeouts are investigated. Shared epoll changes here are limited
to forwarding the submitted length to the follow-up predicate; bulk promotion
belongs to PR #782.
