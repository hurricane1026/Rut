# WebSocket multishot and immediate-send study

This retained study compares the bounded-cache multishot receive mode
(`cache_async`) with the copy control and nginx for the plaintext WebSocket
fixture. It used three repeats, 8 seconds measured after 2 seconds warmup,
192 connections, one frontend worker, four origin workers, and three client
workers. Every echo was validated and measured client errors were zero.

| Payload | Mode | Median messages/s | Observed range | Median p99 |
| ---: | --- | ---: | --- | ---: |
| 64 B | cache_async | 97,574 | 96,698–99,421 | 2.517 ms |
| 64 B | nginx | 83,986 | 82,925–84,427 | 2.729 ms |
| 1 KiB | cache_async | 88,480 | 87,271–88,908 | 2.767 ms |
| 1 KiB | nginx | 77,808 | 76,904–78,307 | 2.777 ms |

The 64 B result is +16.2% versus nginx, with a 7.8% lower median p99. The
1 KiB result is +13.7%, with effectively unchanged p99. These observations
apply to this fixture and host; they are retained benchmark evidence rather
than a global runtime policy recommendation.
