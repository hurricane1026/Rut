#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
BIN=${1:-"$ROOT/build/src/rut"}
BASE_PORT=${RUT_VALIDATION_BASE_PORT:-19840}
OPT_LEVEL=${RUT_VALIDATION_OPT:-2}
ORIGIN_PORT=19890
UNAVAILABLE_PORT=19891
WS_ORIGIN_PORT=19892
TLS_ORIGIN_PORT=19893
VALIDATE_WEBSOCKET=${RUT_VALIDATION_WEBSOCKET:-1}
TMP=$(mktemp -d)
RUT_PID=
ORIGIN_PID=
WS_ORIGIN_PID=
TLS_ORIGIN_PID=

wait_for_exit() {
    local pid=$1
    local attempts=${2:-100}
    local attempt
    for ((attempt = 0; attempt < attempts; attempt++)); do
        if ! kill -0 "$pid" 2>/dev/null; then
            return 0
        fi
        sleep 0.05
    done
    return 1
}

terminate_process() {
    local pid=$1
    if [[ -z "$pid" ]]; then
        return 0
    fi
    kill -TERM "$pid" 2>/dev/null || true
    if ! wait_for_exit "$pid"; then
        kill -KILL "$pid" 2>/dev/null || true
    fi
    wait "$pid" 2>/dev/null || true
}

cleanup() {
    terminate_process "$RUT_PID"
    terminate_process "$ORIGIN_PID"
    terminate_process "$WS_ORIGIN_PID"
    terminate_process "$TLS_ORIGIN_PID"
    rm -rf "$TMP"
}
trap cleanup EXIT

fail() {
    printf 'FAIL: %s\n' "$*" >&2
    if [[ -f "$TMP/rut.log" ]]; then
        sed -n '1,160p' "$TMP/rut.log" >&2
    fi
    exit 1
}

stop_rut() {
    if [[ -n "$RUT_PID" ]]; then
        local pid=$RUT_PID
        kill -TERM "$pid" 2>/dev/null || true
        if ! wait_for_exit "$pid"; then
            kill -KILL "$pid" 2>/dev/null || true
            wait "$pid" 2>/dev/null || true
            RUT_PID=
            fail "rut did not stop within 5 seconds and was killed"
        fi
        local status
        if wait "$pid"; then status=0; else status=$?; fi
        RUT_PID=
        [[ "$status" -eq 0 ]] || fail "rut exited with status $status during shutdown"
    fi
}

wait_fixture() {
    local pid=$1
    local port=$2
    local log=$3
    local name=$4
    if ! python3 "$ROOT/examples/design-validation/probe.py" wait-port \
        --pid "$pid" --port "$port" --timeout 5; then
        sed -n '1,120p' "$log" >&2
        fail "$name fixture did not become ready"
    fi
}

start_rut() {
    local file=$1
    local port=$2
    shift 2
    : >"$TMP/rut.log"
    "$BIN" "$port" --backend epoll --shards 1 --no-pin --drain 0 --opt "$OPT_LEVEL" "$@" \
        "$file" \
        >"$TMP/rut.log" 2>&1 &
    RUT_PID=$!

    for _ in $(seq 1 100); do
        if ! kill -0 "$RUT_PID" 2>/dev/null; then
            wait "$RUT_PID" || true
            fail "$file did not load"
        fi
        if grep -Fq 'Loaded program:' "$TMP/rut.log" &&
            grep -Fq 'Listening on port' "$TMP/rut.log"; then
            kill -0 "$RUT_PID" 2>/dev/null || fail "$file exited during startup"
            return
        fi
        sleep 0.05
    done
    fail "$file did not become ready"
}

assert_body_equals() {
    local context=$1
    local expected=$2
    local expected_file="$TMP/expected-body"
    printf '%s' "$expected" >"$expected_file"
    if ! cmp -s "$expected_file" "$TMP/body"; then
        local actual_size expected_size
        actual_size=$(wc -c <"$TMP/body")
        expected_size=$(wc -c <"$expected_file")
        fail "$context returned an unexpected body ($actual_size bytes, expected $expected_size)"
    fi
}

request() {
    local port=$1
    local path=$2
    local expected_status=$3
    local expected_body=$4
    shift 4

    local status
    status=$(curl --silent --show-error --noproxy '*' --max-time 3 \
        --dump-header "$TMP/headers" --output "$TMP/body" \
        --write-out '%{http_code}' "$@" "http://127.0.0.1:$port$path")
    [[ "$status" == "$expected_status" ]] ||
        fail "$path returned $status, expected $expected_status"
    assert_body_equals "$path" "$expected_body"
}

request_url() {
    local url=$1
    local expected_status=$2
    local expected_body=$3
    shift 3

    local status
    status=$(curl --silent --show-error --noproxy '*' --max-time 5 \
        --dump-header "$TMP/headers" --output "$TMP/body" \
        --write-out '%{http_code}' "$@" "$url")
    [[ "$status" == "$expected_status" ]] ||
        fail "$url returned $status, expected $expected_status"
    assert_body_equals "$url" "$expected_body"
}

request_contains() {
    local port=$1
    local path=$2
    local expected_status=$3
    local expected_text=$4
    shift 4
    local status
    status=$(curl --silent --show-error --noproxy '*' --max-time 5 \
        --dump-header "$TMP/headers" --output "$TMP/body" \
        --write-out '%{http_code}' "$@" "http://127.0.0.1:$port$path")
    [[ "$status" == "$expected_status" ]] ||
        fail "$path returned $status, expected $expected_status"
    grep -Fq "$expected_text" "$TMP/body" || fail "$path body did not contain: $expected_text"
}

request_json_field() {
    local port=$1
    local path=$2
    local expected_status=$3
    local field=$4
    local expected_value=$5
    local status
    status=$(curl --silent --show-error --noproxy '*' --max-time 5 \
        --dump-header "$TMP/headers" --output "$TMP/body" \
        --write-out '%{http_code}' "http://127.0.0.1:$port$path")
    [[ "$status" == "$expected_status" ]] ||
        fail "$path returned $status, expected $expected_status"
    if ! python3 - "$TMP/body" "$field" "$expected_value" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as body:
    payload = json.load(body)
actual = payload.get(sys.argv[2]) if isinstance(payload, dict) else None
if actual != sys.argv[3]:
    raise SystemExit(f"field {sys.argv[2]!r} was {actual!r}, expected {sys.argv[3]!r}")
PY
    then
        fail "$path did not return valid JSON with $field=$expected_value"
    fi
}

assert_http_version() {
    local url=$1
    local expected=$2
    shift 2
    local version
    version=$(curl --silent --show-error --noproxy '*' --max-time 5 \
        --output /dev/null --write-out '%{http_version}' "$@" "$url")
    [[ "$version" == "$expected" ]] ||
        fail "$url used HTTP/$version, expected HTTP/$expected"
}

expect_load_failure() {
    local file=$1
    local expected=$2
    local port=$((BASE_PORT + 30))
    : >"$TMP/rut.log"
    "$BIN" "$port" --backend epoll --shards 1 --no-pin --drain 0 --opt 0 "$file" \
        >"$TMP/rut.log" 2>&1 &
    RUT_PID=$!
    for _ in $(seq 1 200); do
        if grep -Fq 'Listening on port' "$TMP/rut.log"; then
            local pid=$RUT_PID
            RUT_PID=
            terminate_process "$pid"
            fail "$file unexpectedly loaded"
        fi
        if ! kill -0 "$RUT_PID" 2>/dev/null; then
            local status
            if wait "$RUT_PID"; then status=0; else status=$?; fi
            RUT_PID=
            [[ "$status" -ne 0 ]] || fail "$file unexpectedly exited successfully"
            grep -Fq "$expected" "$TMP/rut.log" ||
                fail "$file failed without expected diagnostic: $expected"
            return
        fi
        sleep 0.05
    done
    local pid=$RUT_PID
    RUT_PID=
    terminate_process "$pid"
    fail "$file did not finish its negative load probe within 10 seconds"
}

[[ -x "$BIN" ]] || fail "rut binary is not executable: $BIN"
command -v curl >/dev/null || fail "curl is required"
command -v cmp >/dev/null || fail "cmp is required"
command -v python3 >/dev/null || fail "python3 is required"
command -v openssl >/dev/null || fail "openssl is required"
command -v timeout >/dev/null || fail "timeout is required"

ports=(
    "$ORIGIN_PORT"
    "$UNAVAILABLE_PORT"
    "$TLS_ORIGIN_PORT"
    "$((BASE_PORT + 30))"
)
for offset in $(seq 0 15); do
    if [[ "$VALIDATE_WEBSOCKET" == 0 && "$offset" -eq 11 ]]; then
        continue
    fi
    ports+=("$((BASE_PORT + offset))")
done
if [[ "$VALIDATE_WEBSOCKET" != 0 ]]; then
    ports+=("$WS_ORIGIN_PORT")
fi
python3 - "${ports[@]}" <<'PY' || fail "one or more validation ports are unavailable"
import socket
import sys

ports = [int(value) for value in sys.argv[1:]]
if len(ports) != len(set(ports)):
    raise SystemExit("validation port configuration overlaps")
for port in ports:
    with socket.socket() as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(("127.0.0.1", port))
PY

port=$BASE_PORT
start_rut "$ROOT/examples/design-validation/routing.rut" "$port" \
    --access-log "$TMP/access.log"
request "$port" "/health" 204 ""
request "$port" "/api/users/42?mode=read" 200 \
    '{"id":"42","mode":"read","path":"users/42"}'
request "$port" "/api/users/42" 200 \
    '{"id":"42","mode":"read","path":"users/42"}'
request "$port" "/api/users/41" 404 'Not Found'
request "$port" "/missing" 404 'Not Found'
request "$port" "/search?tag=design&tag=rut" 204 "" \
    -H 'Accept: text/plain' -H 'Accept: application/json'
python3 "$ROOT/examples/design-validation/probe.py" keepalive --port "$port" ||
    fail "HTTP/1.1 keep-alive probe failed"
python3 "$ROOT/examples/design-validation/probe.py" pipeline --port "$port" ||
    fail "HTTP/1.1 pipeline probe failed"
python3 "$ROOT/examples/design-validation/probe.py" concurrency --port "$port" --count 32 ||
    fail "concurrency probe failed"
stop_rut
grep -Fq 'GET /health 204' "$TMP/access.log" || fail "access log did not record /health"
printf 'PASS routing.rut\n'

port=$((BASE_PORT + 13))
start_rut "$ROOT/examples/design-validation/routing.rut" "$port" --shards 2
grep -Fq 'with 2 shard(s)' "$TMP/rut.log" || fail "Rut did not start with two shards"
python3 "$ROOT/examples/design-validation/probe.py" concurrency --port "$port" --count 64 ||
    fail "multi-shard concurrency probe failed"
stop_rut
printf 'PASS routing.rut multi-shard\n'

port=$((BASE_PORT + 1))
start_rut "$ROOT/examples/design-validation/core.rut" "$port"
request "$port" "/loop/accepted" 204 ""
request "$port" "/loop/rejected" 422 'Unknown'
request "$port" "/regex/rut" 204 ""
request "$port" "/regex/123" 404 'Not Found'
request "$port" "/optional" 200 '{"value":"present"}' -H 'X-Value: present'
request "$port" "/optional" 404 'Not Found'
request "$port" "/response" 202 '{"status":202,"observed":"/response"}'
grep -Fqi 'X-Path: /response' "$TMP/headers" || fail "response set header missing"
grep -Fqi 'X-Path: tail' "$TMP/headers" || fail "response add header missing"
grep -Fqi 'X-Observed: /response' "$TMP/headers" || fail "response header read missing"
if grep -Fqi 'X-Discard:' "$TMP/headers"; then fail "response remove header failed"; fi
stop_rut
printf 'PASS core.rut\n'

port=$((BASE_PORT + 2))
start_rut "$ROOT/examples/design-validation/data.rut" "$port"
request "$port" "/data?tag=core&tag=jit" 200 \
    '{"path":"/data?tag=core&tag=jit","answer":42,"tags":["core","jit"],"meta":{"ok":true}}'
request "$port" "/error" 503 '{"ok":false}'
stop_rut
printf 'PASS data.rut\n'

port=$((BASE_PORT + 3))
start_rut "$ROOT/examples/design-validation/request.rut" "$port"
request "$port" "/upload" 201 \
    '{"body":"payload","token":"secret","session":"ok"}' \
    -X POST --data-binary 'payload' -H 'X-Token: secret' -H 'Cookie: sid=ok'
request "$port" "/upload" 401 'Unauthorized' \
    -X POST --data-binary 'payload' -H 'X-Token: wrong' -H 'Cookie: sid=ok'
request "$port" "/headers" 200 \
    '{"values":["one","two"],"host":"127.0.0.1"}' \
    -H 'Host: 127.0.0.1' -H 'X-Value: one' -H 'X-Value: two'
request "$port" "/version" 204 ""
request "$port" "/version" 505 'Unknown' --http1.0
stop_rut
printf 'PASS request.rut\n'

port=$((BASE_PORT + 4))
start_rut "$ROOT/examples/design-validation/middleware.rut" "$port"
request "$port" "/chain" 201 '{"stage":"after","ok":true}'
grep -Fqi 'X-Rut-Stage: after-wait' "$TMP/headers" || fail "chain response header missing"
stop_rut
printf 'PASS middleware.rut\n'

port=$((BASE_PORT + 5))
start_rut "$ROOT/examples/design-validation/state.rut" "$port"
request "$port" "/limited" 200 'OK'
request "$port" "/limited" 200 'OK'
request "$port" "/limited" 429 'Too Many Requests'
stop_rut
printf 'PASS state.rut\n'

port=$((BASE_PORT + 6))
start_rut "$ROOT/examples/design-validation/modules/main.rut" "$port"
request "$port" "/imported" 202 '{"imported":true}'
stop_rut
printf 'PASS modules/main.rut\n'

port=$((BASE_PORT + 15))
start_rut "$ROOT/examples/design-validation/operations.rut" "$port"
request_json_field "$port" "/stats" 200 scope shard
request_json_field "$port" "/runtime-metrics" 200 scope process
stop_rut
printf 'PASS operations.rut snapshots\n'

port=$((BASE_PORT + 7))
start_rut "$ROOT/examples/design-validation/limits.rut" "$port"
request "$port" "/json" 200 '{"value":"small"}' -H 'X-Large: small'
large=$(printf '%7500s' '' | tr ' ' x)
request "$port" "/json" 500 'Internal Server Error' -H "X-Large: $large"
request "$port" "/body" 500 'Internal Server Error' -H "X-Large: $large"
request "$port" "/status?item=one" 500 'Internal Server Error'
stop_rut
printf 'PASS limits.rut\n'

port=$((BASE_PORT + 8))
start_rut "$ROOT/examples/design-validation/transport.rut" "$port" --metrics
request_url "http://127.0.0.1:$port/transport" 200 \
    '{"path":"/transport","http11":true}' --http2-prior-knowledge
assert_http_version "http://127.0.0.1:$port/transport" 2 --http2-prior-knowledge
request_contains "$port" "/metrics" 200 'rut_requests_total'
grep -Eq '^rut_requests_total [0-9]+$' "$TMP/body" ||
    fail "/metrics did not contain a numeric rut_requests_total sample"
stop_rut
printf 'PASS transport.rut h2c/metrics\n'

port=$((BASE_PORT + 9))
cert="$ROOT/tests/fixtures/localhost_cert.pem"
key="$ROOT/tests/fixtures/localhost_key.pem"
sni_cert="$ROOT/tests/fixtures/api_example_cert.pem"
start_rut "$ROOT/examples/design-validation/transport.rut" "$port" \
    --tls-cert "$cert" --tls-key "$key" \
    --tls-sni api.example.test "$sni_cert" "$key" --h2
request_url "https://127.0.0.1:$port/transport" 200 \
    '{"path":"/transport","http11":true}' --insecure --http1.1
request_url "https://localhost:$port/transport" 200 \
    '{"path":"/transport","http11":true}' --cacert "$cert" --http1.1 \
    --resolve "localhost:$port:127.0.0.1"
request_url "https://127.0.0.1:$port/transport" 200 \
    '{"path":"/transport","http11":true}' --insecure --http2
assert_http_version "https://127.0.0.1:$port/transport" 2 --insecure --http2
request_url "https://api.example.test:$port/transport" 200 \
    '{"path":"/transport","http11":true}' --cacert "$sni_cert" --http1.1 \
    --resolve "api.example.test:$port:127.0.0.1"
if ! timeout 5 openssl s_client -connect "127.0.0.1:$port" \
    -servername api.example.test -CAfile "$sni_cert" </dev/null 2>/dev/null |
    openssl x509 -outform PEM >"$TMP/sni-peer.pem"; then
    fail "SNI certificate probe did not complete within 5 seconds"
fi
openssl verify -CAfile "$sni_cert" -verify_hostname api.example.test \
    "$TMP/sni-peer.pem" >/dev/null ||
    fail "SNI peer certificate does not match api.example.test"
stop_rut
printf 'PASS transport.rut TLS/ALPN/SNI\n'

port=$((BASE_PORT + 12))
start_rut "$ROOT/examples/design-validation/transport.rut" "$port" \
    --tls-cert "$cert" --tls-key "$key" --tls-client-ca "$cert"
set +e
curl --silent --show-error --noproxy '*' --max-time 3 --insecure \
    --output /dev/null "https://127.0.0.1:$port/transport" >/dev/null 2>&1
missing_client_status=$?
set -e
[[ "$missing_client_status" -ne 0 ]] || fail "mTLS accepted a client without a certificate"
set +e
curl --silent --show-error --noproxy '*' --max-time 3 --insecure \
    --cert "$sni_cert" --key "$key" \
    --output /dev/null "https://127.0.0.1:$port/transport" >/dev/null 2>&1
untrusted_client_status=$?
set -e
[[ "$untrusted_client_status" -ne 0 ]] ||
    fail "mTLS accepted a client certificate outside the configured CA"
request_url "https://127.0.0.1:$port/transport" 200 \
    '{"path":"/transport","http11":true}' --insecure --http1.1 \
    --cert "$cert" --key "$key"
stop_rut
printf 'PASS transport.rut mTLS\n'

python3 "$ROOT/examples/design-validation/origin.py" --port "$ORIGIN_PORT" \
    >"$TMP/origin.log" 2>&1 &
ORIGIN_PID=$!
wait_fixture "$ORIGIN_PID" "$ORIGIN_PORT" "$TMP/origin.log" "HTTP origin"

port=$((BASE_PORT + 10))
start_rut "$ROOT/examples/design-validation/proxy.rut" "$port"
request "$port" "/proxy" 202 'origin-ok'
grep -Fqi 'X-Rut-Proxy: validated' "$TMP/headers" || fail "proxy response header missing"
grep -Fqi 'X-Origin: local' "$TMP/headers" || fail "buffered origin response header missing"
request "$port" "/stream" 200 'origin-ok'
grep -Fqi 'X-Origin: local' "$TMP/headers" || fail "streaming origin response header missing"
stream_body=$(printf '%17000s' '' | tr ' ' x)
request "$port" "/stream-oversized" 200 "$stream_body"
grep -Fqi 'X-Origin: local' "$TMP/headers" ||
    fail "oversized streaming origin response header missing"
request "$port" "/rewrite" 200 '/rewritten|yes'
request_url "http://127.0.0.1:$port/proxy" 202 'origin-ok' --http2-prior-knowledge
assert_http_version "http://127.0.0.1:$port/proxy" 2 --http2-prior-knowledge
request_url "http://127.0.0.1:$port/post" 200 '/post|payload' \
    --http2-prior-knowledge -X POST --data-binary 'payload'
request "$port" "/oversized" 502 'Bad Gateway'
request "$port" "/unavailable" 502 'Bad Gateway'
stop_rut
printf 'PASS proxy.rut\n'

python3 "$ROOT/examples/design-validation/origin.py" --port "$TLS_ORIGIN_PORT" \
    --cert "$cert" --key "$key" --client-ca "$cert" >"$TMP/tls-origin.log" 2>&1 &
TLS_ORIGIN_PID=$!
wait_fixture "$TLS_ORIGIN_PID" "$TLS_ORIGIN_PORT" "$TMP/tls-origin.log" "TLS origin"
port=$((BASE_PORT + 14))
start_rut "$ROOT/examples/design-validation/proxy-tls.rut" "$port" \
    --upstream-tls-ca "$cert" --upstream-tls-cert "$cert" --upstream-tls-key "$key"
request "$port" "/mismatched-proxy" 502 'Bad Gateway'
request "$port" "/secure-proxy" 200 'origin-ok'
stop_rut
printf 'PASS proxy-tls.rut verified TLS/mTLS origin\n'

if [[ "$VALIDATE_WEBSOCKET" != 0 ]]; then
    python3 "$ROOT/examples/design-validation/origin.py" --port "$WS_ORIGIN_PORT" \
        >"$TMP/ws-origin.log" 2>&1 &
    WS_ORIGIN_PID=$!
    wait_fixture "$WS_ORIGIN_PID" "$WS_ORIGIN_PORT" "$TMP/ws-origin.log" "WebSocket origin"
    port=$((BASE_PORT + 11))
    start_rut "$ROOT/examples/design-validation/websocket.rut" "$port"
    python3 "$ROOT/examples/design-validation/probe.py" websocket --port "$port" ||
        fail "WebSocket upgrade probe failed"
    stop_rut
    printf 'PASS websocket.rut\n'
fi

expect_load_failure "$ROOT/examples/design-validation/invalid/duplicate-json-key.rut" \
    'json object field names must be unique'
expect_load_failure "$ROOT/examples/design-validation/invalid/hash-target-surface.rut" \
    'only Cache<IP, i64>(capacity: N) is supported'
expect_load_failure "$ROOT/examples/design-validation/invalid/invalid-regex.rut" 'invalid regex'
expect_load_failure "$ROOT/examples/design-validation/invalid/unsafe-forward-header.rut" \
    'Content-Length'
expect_load_failure "$ROOT/examples/design-validation/invalid/unresolved-upstream.rut" \
    'register routes failed'
printf 'PASS expected compile/load failures\n'

python3 "$ROOT/examples/design-validation/reload_probe.py" --rut "$BIN" ||
    fail "route-triggered reload failed"
printf 'PASS route-triggered reload\n'

if [[ ${RUT_VALIDATION_PROCESS_TESTS:-1} != 0 ]]; then
    python3 "$ROOT/tests/test_process_reload.py" --rut "$BIN" || fail "process reload failed"
    python3 "$ROOT/tests/test_backend_selection.py" --rut "$BIN" ||
        fail "backend selection failed"
    printf 'PASS reload/backend process behavior\n'
fi

printf 'All Rut design validation programs compiled and served successfully.\n'
