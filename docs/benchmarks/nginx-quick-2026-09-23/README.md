# Quick nginx / Rut benchmark — 2026-09-23

This run exercises the explicit quick profile on all four HTTP scenarios at
concurrency 1 / 32 / 128 (12 comparisons, 24 engine samples). Each sample has a
1-second warmup and 2-second measurement, with one repeat and nginx first.
Static responses contain 16 bytes; strict converter proxy responses contain
1024 bytes. Keepalive uses HTTP/1.1 implicit persistence. Frontend CPU 2,
origin CPU 3 and wrk CPUs 4,5 are distinct physical cores on an Intel i7-10700.
The host was not exclusively reserved and frequency was not locked. No builds
or test suites ran during measurement.

The runtime is the archived Release/JIT binary attributed to
`ddf27ee6e4a57929bc99233a22646f48510a4392`, not a rebuild of current main.
All three executable hashes were checked against retained provenance before
execution; see [provenance.json](provenance.json). The converter's exact source
revision is unknown. Harness base is `601f144e` plus this PR's changes;
[harness-source-sha256.json](harness-source-sha256.json) pins the runner sources.

The quick run below was captured before the default changed to acceptance;
its recorded runner hashes and raw evidence are unchanged.

## Results

Actual elapsed time: **78.44 seconds**, exit **0**. All **24/24 samples** were
valid; all eight frontend response preflights passed, with no recorded warmup
or measurement errors. `status.json` confirms completed cleanup; no benchmark
containers remained. Scheduled load is 72 seconds, down from the old default's
720 seconds (90% reduction in scheduled load).

See [REPORT.md](REPORT.md) for all 12 comparisons and p99 latency. At concurrency
32 / 128, Rut/nginx throughput was 1.42× / 1.47× for static keepalive and
1.20× / 1.26× for proxy keepalive. Static close at concurrency 32 was 0.92× and
proxy keepalive at concurrency 1 was 0.98×. Higher throughput did not always
mean lower tail latency: static keepalive at concurrency 128 had Rut p99
4,448 µs versus nginx 1,280 µs.

[results.json](results.json), [summary.csv](summary.csv),
[environment.json](environment.json), [status.json](status.json) and
[wall-time.txt](wall-time.txt) retain machine-readable results.
[evidence.tar.gz](evidence.tar.gz) contains full raw wrk logs, CPU samples,
configs, generated Rut programs, server logs and commands, plus the initial
setup failure. No executables are embedded. Harness tests: **22 passed**;
[test-results.log](test-results.log) retains the output.

## Reproduction

From the repository root, substitute the same archived executable paths:

```sh
python3 scripts/nginx_benchmark/run.py \
  --rut /path/to/archived/rut --converter /path/to/archived/converter \
  --wrk /path/to/archived/wrk --output /tmp/nginx-quick \
  --server-cpu 2 --origin-cpu 3 --client-cpus 4,5 \
  --keepalive-header implicit --profile quick
python3 scripts/nginx_benchmark/summarize.py /tmp/nginx-quick
```

On this host, `sg docker -c '...'` activated existing Docker group membership.
The first attempt failed before load because enforcing SELinux denied nginx's
read-only configuration mount. The successful attempt used a fresh empty
output directory labeled with `chcon -t container_file_t`. The failed attempt
and its timing are retained in the evidence archive.

## Interpretation

This is a short functionality and turnaround-time check, not performance
acceptance. One repeat, short samples and nginx-first ordering limit the
throughput comparison. Use `--profile full` and appropriate order controls for
performance conclusions. HTTPS and the body-size matrix were not run.
The old default's 720-second load budget is a calculation, not a separately
timed baseline run; actual elapsed time includes startup, preflight and cleanup.
