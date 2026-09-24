# BoringSSL native-body full-96 acceptance

Source: `e2866fe02a0d921be6e24a6eb1ccc768c492441c`

Cells: 96; raw samples: 576.

Raw verification: **PASS**

Performance gate: **FAIL**

| Transport | Body | Pass | Below 1.10 | Invalid |
|---|---:|---:|---:|---:|
| http | 16 | 9 | 3 | 0 |
| http | 1024 | 10 | 2 | 0 |
| http | 65536 | 6 | 6 | 0 |
| http | 1048576 | 0 | 12 | 0 |
| https | 16 | 12 | 0 | 0 |
| https | 1024 | 12 | 0 | 0 |
| https | 65536 | 11 | 1 | 0 |
| https | 1048576 | 3 | 9 | 0 |

Cells below 1.10:
- http static-close body=16 concurrency=1: ratio=1.065807
- http proxy-close body=16 concurrency=32: ratio=1.057007
- http proxy-close body=16 concurrency=128: ratio=1.065017
- http static-close body=1024 concurrency=1: ratio=1.072147
- http proxy-close body=1024 concurrency=32: ratio=1.024379
- http static-close body=65536 concurrency=32: ratio=1.042340
- http static-close body=65536 concurrency=128: ratio=1.032983
- http static-keepalive body=65536 concurrency=1: ratio=1.027057
- http proxy-close body=65536 concurrency=1: ratio=0.855349
- http proxy-close body=65536 concurrency=128: ratio=1.026502
- http proxy-keepalive body=65536 concurrency=1: ratio=0.825326
- http static-close body=1048576 concurrency=1: ratio=0.889361
- http static-close body=1048576 concurrency=32: ratio=0.908588
- http static-close body=1048576 concurrency=128: ratio=0.834840
- http static-keepalive body=1048576 concurrency=1: ratio=0.931241
- http static-keepalive body=1048576 concurrency=32: ratio=0.898150
- http static-keepalive body=1048576 concurrency=128: ratio=0.831265
- http proxy-close body=1048576 concurrency=1: ratio=1.059661
- http proxy-close body=1048576 concurrency=32: ratio=0.448770
- http proxy-close body=1048576 concurrency=128: ratio=0.417418
- http proxy-keepalive body=1048576 concurrency=1: ratio=0.645108
- http proxy-keepalive body=1048576 concurrency=32: ratio=0.583384
- http proxy-keepalive body=1048576 concurrency=128: ratio=0.581033
- https proxy-keepalive body=65536 concurrency=1: ratio=0.974467
- https static-close body=1048576 concurrency=1: ratio=0.012341
- https static-close body=1048576 concurrency=32: ratio=1.089486
- https static-close body=1048576 concurrency=128: ratio=0.913615
- https proxy-close body=1048576 concurrency=1: ratio=1.014333
- https proxy-close body=1048576 concurrency=32: ratio=0.879339
- https proxy-close body=1048576 concurrency=128: ratio=0.776029
- https proxy-keepalive body=1048576 concurrency=1: ratio=0.929517
- https proxy-keepalive body=1048576 concurrency=32: ratio=0.892211
- https proxy-keepalive body=1048576 concurrency=128: ratio=0.884864
