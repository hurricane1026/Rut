# Optional Linkerd / Envoy proxy benchmark

This is an optional Linux benchmark tool; it does not change Rut's runtime or add Rut build dependencies. It compares one proxy hop over plaintext HTTP/1.1 keepalive at concurrency 128 for 4 KiB, 64 KiB, 256 KiB, and 1 MiB responses. Linkerd means a stock **single inbound sidecar** with a real Linkerd control plane and identity, not a complete service mesh or an external gateway. The client shares only the kind worker's network namespace; it is not in the application Pod.

`prepare.py` writes the deterministic response payloads, Rut DSL files, Nginx/Envoy configuration, and unique ConfigMaps. `run_matrix.py` runs one Pod at a time in an interleaved 3-repeat matrix, records preflight and runtime evidence, then deletes only the Pod it created. `summarize.py` refuses invalid or incomplete samples unless `--allow-partial` is requested. The scripts do not create/delete a Kubernetes cluster, change host firewall rules, install software on the host, or package binaries, kubeconfigs, keys, or result data.

## Prerequisites

- Linux x86-64, Docker Buildx, kind, kubectl, Git, tar, sha256sum, the Linkerd CLI, Python 3, and `taskset` in the kind node image. The cluster must use cgroup v2 with no CPU quota on timed containers.
- An otherwise idle host and a dedicated two-node kind cluster. Check the physical CPU topology with `lscpu -e`; use disjoint physical cores for proxy (2), origin (3,4,8,9), client (5,7), and cluster helpers (6,14). Do not use this CPU map blindly on another machine.
- Rut binaries built from a tree that supports the `.rps` and `.throughput` hints. Each selected directory must contain a compatible `rut` and its matching sibling `rut-compile`. This benchmark PR is based on `main` and contains no hint-language runtime change. The measured runtime and compiler binaries were both built from source commit `9543573a`; its runtime files matched the later tree `defea4bb`. Provide an equivalent supported pair and keep the SHA-256 values emitted by `prepare.py`.
- A local checkpoint directory that will be mounted into the kind worker at `/benchmark`. It must be dedicated to this run. Never point the helper-pinning option at a shared or production cluster.

The measured tool versions were kind `v0.33.0`, Kubernetes node image `kindest/node:v1.35.8@sha256:07b2536e30b803ed61d1677a79df6115f798ce64c80f9e22f6ed45afd09323c0`, Linkerd CLI `edge-26.10.1` (SHA-256 `66d634f5318c8016f0b5face246a688964b6e2c86d6c3be34be68ab9fcd2a8cc`), Gateway API `v1.5.1`, and pinned Envoy/Nginx image digests in `prepare.py`. These are benchmark inputs, not dependencies of Rut.

Build the optional client image from this repository root. It includes `/bin/sh`, `curl`, and `wrk`; `wrk` is built from the pinned source revision and statically linked against this repository's BoringSSL sources and the C++ runtime needed by BoringSSL. No system OpenSSL package, library, or CLI is added by this benchmark image recipe. Override the tag with a unique local name if needed:

```sh
CHECKPOINT=/absolute/path/to/benchmark-checkpoint
mkdir -p "$CHECKPOINT"
git submodule update --init third_party/boringssl
WRK_COMMIT=a211dd5a7050b1f9e8a9870b95513060e72ac4a0
WRK_CHECKOUT="$CHECKPOINT/wrk-checkout"
WRK_SOURCE="$CHECKPOINT/wrk-source"
mkdir -p "$WRK_CHECKOUT" "$WRK_SOURCE"
git -C "$WRK_CHECKOUT" init -q
git -C "$WRK_CHECKOUT" remote add origin https://github.com/wg/wrk.git
git -C "$WRK_CHECKOUT" fetch --depth 1 origin "$WRK_COMMIT"
git -C "$WRK_CHECKOUT" checkout -q --detach FETCH_HEAD
test "$(git -C "$WRK_CHECKOUT" rev-parse HEAD)" = "$WRK_COMMIT"
git -C "$WRK_CHECKOUT" archive HEAD | tar -x -C "$WRK_SOURCE"
printf '%s\n' "$WRK_COMMIT" > "$WRK_SOURCE/.benchmark-source-revision"
docker buildx build --load \
  --build-context wrk-source="$WRK_SOURCE" \
  -f scripts/proxy_benchmark/Dockerfile.client \
  -t proxy-benchmark-client:local .
```

The kind worker image supplies `taskset`; `run_matrix.py` uses it through `docker exec`. The client itself is constrained with Docker `--cpuset-cpus`. The Rut Pod needs its runtime shared libraries and the exact `clang` and `ld` executables used by the selected Rut toolchain, because the runtime's native-artifact compiler launches those absolute paths. Collect shared objects with the included standard-library-only helper; it uses the host `ldd` command and adds no package/build dependency:

```sh
python3 scripts/proxy_benchmark/collect_runtime_libs.py \
  --output "$CHECKPOINT/runtime-libs" \
  "$RUT_RPS_DIR/rut" "$RUT_RPS_DIR/rut-compile" \
  "$RUT_THROUGHPUT_DIR/rut" "$RUT_THROUGHPUT_DIR/rut-compile" \
  "$(readlink -f "$(command -v clang)")" "$(readlink -f "$(command -v ld)")"
mkdir -p "$CHECKPOINT/runtime-tools"
cp "$(readlink -f "$(command -v clang)")" "$CHECKPOINT/runtime-tools/clang"
cp "$(readlink -f "$(command -v ld)")" "$CHECKPOINT/runtime-tools/ld"
```

Pass those paths to `prepare.py`. Keep all binaries and the library bundle under the checkpoint so the kind worker can mount and read them. Do not use libraries from an unrelated compiler installation.

## Prepare an isolated kind cluster

Create a unique cluster name, checkpoint, and kubeconfig. The `extraMounts` entry must use the absolute host checkpoint path. This creates only kind-owned networking; no manual host firewall or iptables changes are part of the procedure.

```yaml
# Save as $CHECKPOINT/kind.yaml after replacing /absolute/checkpoint.
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
nodes:
- role: control-plane
  labels:
    benchmark-role: control
- role: worker
  labels:
    benchmark-role: worker
  extraMounts:
  - hostPath: /absolute/checkpoint
    containerPath: /benchmark
```

Use the pinned node image above when creating the cluster. Set a restrictive umask before creating kubeconfig or Linkerd installation files:

```sh
umask 077
kind create cluster --name "$CLUSTER" \
  --config "$CHECKPOINT/kind.yaml" \
  --image 'kindest/node:v1.35.8@sha256:07b2536e30b803ed61d1677a79df6115f798ce64c80f9e22f6ed45afd09323c0' \
  --kubeconfig "$CHECKPOINT/kubeconfig" --wait 120s
docker update --cpuset-cpus 6,14 "$CLUSTER-control-plane"
docker update --cpuset-cpus 2-9,14 "$CLUSTER-worker"
kubectl --kubeconfig "$CHECKPOINT/kubeconfig" taint nodes \
  "${CLUSTER}-control-plane" node-role.kubernetes.io/control-plane:NoSchedule-
kubectl --kubeconfig "$CHECKPOINT/kubeconfig" apply -f \
  https://github.com/kubernetes-sigs/gateway-api/releases/download/v1.5.1/standard-install.yaml
chmod 600 "$CHECKPOINT/kubeconfig"
docker exec "$CLUSTER-worker" crictl pull 'nginx@sha256:1854da86e82d5dfb49a8f3d78b099adcc7e36608b207146ed95cd47937938a40'
docker exec "$CLUSTER-worker" crictl pull 'envoyproxy/envoy@sha256:57e14a549d7bd43c8d3f6d03e8cfa653e037d4b38e133acd9b54f38c524401b4'
```

Download the official Linkerd CLI `edge-26.10.1` release asset and verify the SHA-256 above. Install Linkerd with its generated per-cluster identity; do not set identity-disabled flags or use a fake controller. Save the rendered install manifests and kubeconfig with mode `0600` because they can contain credentials. Pin the control plane to the labeled control node:

```sh
curl -fL \
  https://github.com/linkerd/linkerd2/releases/download/edge-26.10.1/linkerd2-cli-edge-26.10.1-linux-amd64 \
  -o "$CHECKPOINT/linkerd"
echo '66d634f5318c8016f0b5face246a688964b6e2c86d6c3be34be68ab9fcd2a8cc  '"$CHECKPOINT/linkerd" | sha256sum -c -
chmod 700 "$CHECKPOINT/linkerd"
LINKERD="$CHECKPOINT/linkerd"
"$LINKERD" --kubeconfig "$CHECKPOINT/kubeconfig" check --pre
"$LINKERD" --kubeconfig "$CHECKPOINT/kubeconfig" install --crds > "$CHECKPOINT/linkerd-crds.yaml"
kubectl --kubeconfig "$CHECKPOINT/kubeconfig" apply -f "$CHECKPOINT/linkerd-crds.yaml"
"$LINKERD" --kubeconfig "$CHECKPOINT/kubeconfig" install \
  --set nodeSelector.benchmark-role=control \
  --set proxy.runtime.workers.minimum=1 \
  --set proxyInit.runAsRoot=true > "$CHECKPOINT/linkerd-control-plane.yaml"
chmod 600 "$CHECKPOINT/kubeconfig" "$CHECKPOINT/linkerd-crds.yaml" "$CHECKPOINT/linkerd-control-plane.yaml"
kubectl --kubeconfig "$CHECKPOINT/kubeconfig" apply -f "$CHECKPOINT/linkerd-control-plane.yaml"
"$LINKERD" --kubeconfig "$CHECKPOINT/kubeconfig" check
kubectl --kubeconfig "$CHECKPOINT/kubeconfig" create namespace proxy-benchmark
```

The helper-pinning flag below pins all existing worker-node threads to CPUs 6 and 14, then records and checks their affinity. It requires an otherwise empty, benchmark-only kind worker. It never pins the host or control-plane container. Timed server processes are separately pinned by `run_matrix.py` and every container thread's affinity is checked; the script also rejects a CPU quota.

Load the Nginx and Envoy image references from `prepare.py` into the kind nodes (or ensure the worker can pull them), and load the client image into kind:

```sh
kind load docker-image --name "$CLUSTER" proxy-benchmark-client:local
```

## Configure and run

Use fresh directories. `--output` must be empty. Both Rut directories need sibling `rut` and `rut-compile` files; each binary/compiler pair is hashed in `benchmark.json`. `prepare.py` verifies the explicit kubeconfig context, kind worker identity/mount, node label, namespace, Linkerd readiness, and helper affinity. The two generated ConfigMaps use a random run prefix and `kubectl create`, so an existing resource is never overwritten.

```sh
python3 scripts/proxy_benchmark/prepare.py \
  --checkpoint "$CHECKPOINT" --output "$RESULTS" \
  --kubeconfig "$CHECKPOINT/kubeconfig" --cluster-name "$CLUSTER" \
  --worker-container "${CLUSTER}-worker" --worker-node "${CLUSTER}-worker" \
  --rut-rps-dir "$RUT_RPS_DIR" --rut-throughput-dir "$RUT_THROUGHPUT_DIR" \
  --runtime-libs "$CHECKPOINT/runtime-libs" \
  --clang "$CHECKPOINT/runtime-tools/clang" --ld "$CHECKPOINT/runtime-tools/ld" \
  --client-image proxy-benchmark-client:local \
  --verify-cluster --pin-worker-helpers --apply-configmaps
python3 scripts/proxy_benchmark/run_matrix.py --config "$RESULTS/benchmark.json"
python3 scripts/proxy_benchmark/summarize.py --config "$RESULTS/benchmark.json"
```

Defaults are 3 repeats, 2 s warmup, 10 s measured duration, and concurrency 128. The deterministic interleave is stored in `samples/schedule.json`; each sample includes its commands, Pod manifest/status, proxy metrics (for Linkerd), CPU/cgroup checks, HTTP/1.1 and body hash preflight, warmup and measurement output, and validation marker. The first 4 KiB sample per engine additionally checks 100 marked requests reuse one downstream and one upstream HTTP/1.1 connection. Failed cells stop the run, retain diagnostics, and do not enter the valid index. Resume uses the same `benchmark.json` and existing index. For a smoke run use `run_matrix.py --limit 1` with a fresh output directory; do not treat smoke results as measurements.

For each sample the runner records the frontend executable path, SHA-256, and on-disk byte size (including any debug sections), plus the de-duplicated file sizes and hashes of mapped shared objects. It records separate proxy and origin RSS/PSS totals from `/proc/<pid>/smaps_rollup`. Resource snapshots are taken while idle, after warmup, and up to three times during the measured `wrk` window (around 2, 5, and 8 seconds). Each load snapshot records monotonic window offsets and client container state before and after collection; a snapshot is accepted only when the client remained running, collection completed within the configured measurement duration, and every process row was readable. `resources-summary.json` marks whether all expected snapshots were collected. RSS/PSS are sampled values, not process peaks or memory integrals; missing or incomplete measurements remain `null` and are never inferred from the older comparison run, which did not collect memory data.

After saving results, remove the benchmark namespace and this dedicated cluster explicitly. The matrix runner only deletes its own uniquely named Pods; it leaves ConfigMaps and cluster lifecycle to the operator:

```sh
kubectl --kubeconfig "$CHECKPOINT/kubeconfig" delete namespace proxy-benchmark
kind delete cluster --name "$CLUSTER" --kubeconfig "$CHECKPOINT/kubeconfig"
```

## Offline checks

Run `python3 -m unittest discover -s scripts/proxy_benchmark -p 'test_*.py'` to validate deterministic payload/config generation, CPU masks, Pod shape, schedule, and summary parsing without Docker or Kubernetes. The scripts were extracted from a completed 48-cell run, but the extracted CLI has not itself been rerun end-to-end; use the preflight evidence created by each new run before interpreting its measurements.
