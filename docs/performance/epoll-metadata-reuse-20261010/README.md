# Metadata parse reuse (default-off research)

RUT_STUDY_REQUEST_METADATA_PARSE_REUSE=on borrows the complete initial ParsedRequest synchronously, avoiding a second HTTP parse during metadata capture. No header-table copy, heap allocation or Connection size change. Request-accounting reset and metadata reset do not mutate recv_buf, and no views escape this call. Invalid/incomplete parses retain original fallback behavior. Fragment/target validation, client header inventory, chunk/body framing, raw target witnesses and logging remain the original code.

With prior validation reuse on, policy parse reuse off, BPF confirms1 policy inspector and3 parser entries per request. Metadata helper is inlined at hot call sites; a zero out-of-line helper probe is not evidence that metadata capture is skipped.

Three serial rotations (8s+2s warmup),1KiB persistent proxy,128 clients,one frontendCPU2,four pinned originsCPUs3,4,8,9,clientCPUs5,7; same binary off/on plus nginx1.29.7 multi_accept on. Median off78,548 RPS/p992.464ms; on80,523/2.424; nginx57,983/2.433. Paired throughput -0.99%,+2.64%,+0.42%; median+2.51%. Small noisy candidate; no large or universal gain claimed, default off retained. All9cells zero errors. Earlier unsuccessful policy parse experiment remains off.

4 Release CTests and ASan+UBSan test_splice pass (no leak detection). New metadata equivalence test covers query/fragment,partial upload,WebSocket headers,duplicate Connection and pipeline suffix without changing input bytes.10 real TCP off/on cases match, including complete/partial/zero-length body,identical duplicate CL,chunked,Expect,fragment/absolute target and legacy unknown-method fallback. Unknown methods preserve existing fallback status; the test compares variants instead of inventing a new rejection requirement. Format/diff checks passed before subsequent independent syscall work.

User prioritizes syscall optimization next; SIMD follow-up is https://github.com/hurricane1026/Rut/issues/788 . Full artifact root: /home/hurricane/private/code/rut-performance-checkpoints/epoll-metadata-reuse-20261010.
