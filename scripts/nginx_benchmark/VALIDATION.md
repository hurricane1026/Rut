# Extraction validation

These are local checks of the extracted tool, separate from the historical
72-measurement snapshot. Runtime binaries matched the original baseline.

- Seven harness unit tests pass: HTTP body/EOF checks, server-declared close,
  invalid baselines/repeats/warmup gating, and killing both wrapper and load
  child on a command timeout.
- CLI help and Python lint/format checks pass. The wrk instrumentation patch
  applies cleanly to the documented pinned wrk commit.
- Short real smoke: `--scenarios static-close --concurrency 1 32 --repeats 1
  --warmup 1 --duration 1`. Both engines / both levels pass; exit 0,
  `complete=true, valid=true`, and the generated report shows valid groups.
- Four-scenario smoke with those short settings reproduced RUT EOF during
  proxy keepalive response preflight. The tool exited 2, retained partial
  results with `complete=false, valid=false`, and masked their capacity
  comparisons. This is a retained runtime failure, not an all-scenario pass.
- Extracted independent diagnosis: static keepalive and proxy close,
  concurrency 32, wrk 3 seconds followed by asyncio 2 seconds. Completed with
  exit 1 and invalid evidence retained. nginx had no errors; RUT static wrk
  recorded 88,630 read errors, while the slower asyncio client did not
  reproduce that case. RUT proxy asyncio recorded 6,315 complete responses
  and 4,585 response-header EOFs. These counts are a separate diagnostic run,
  not replacements for historical measurements.
- SIGTERM during an active 20-second wrk warmup: exit 2 and incomplete status;
  owned frontend/origin containers and the GNU time/wrk process group were
  gone. Benchmark ports were no longer listening after cleanup.
- The first port preflight rejected harmless TCP TIME_WAIT state after a
  completed smoke. It now uses SO_REUSEADDR for the availability probe, like
  the actual servers, while an active listener still prevents binding.

Only the fast tooling unit tests run in the added CI workflow. The real local
benchmark is opt-in; production EOF fixes and optimization remain separate.
