#!/bin/bash
set -e
export RUT_STUDY_HTTP_COALESCE_CLOSE=on RUT_STUDY_HTTP_DIRECT_CLOSE=on RUT_STUDY_HTTP_INITIAL_RECV_ONCE=on
unset DOCKER_HOST
python3 /tmp/rut-policy-boundary/relay.py --rut /tmp/rut-ws-pr-20261010-build/src/rut --converter /tmp/rut-ws-pr-20261010-build/src/rut-nginx-convert --wrk /home/hurricane/private/code/rut-nginx-gap-next-bench-20261004/wrk-boringssl-src2 --output "$1" --engines epoll --origin-workers 4 --origin-cpus 3,4,8,9 --origin-reuseport on --origin-pin-workers --server-cpu 2 --client-cpus 5,7 --workers 1 --front-port 8604 --origin-port 8704 --concurrency 128 --keepalive-header implicit --proxy-profile native-streaming --native-origin-reuse on --native-request-policy omit-connection --native-nginx-buffering off --nginx-buffering off --nginx-buffer-kib 16 --scenarios "$2" --body-size 1024 --duration 1 --warmup 1 --repeats 1
