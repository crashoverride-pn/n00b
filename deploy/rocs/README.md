# rocs service deployment

This directory contains the JSON Kubernetes deployment example for the
reference rocs service. It avoids cluster access during tests, static cloud
credentials, and alternate manifest formats.

## Local smoke path

From the repository root, build the service binary through the canonical build
wrapper:

```sh
NCC_PATH=/usr/local/bin/ncc N00B_TEST=1 N00B_SKIP_VCS_CHECK=1 \
N00B_BUILD_TARGETS='n00b-rocs-service test_rocs_service_smoke' \
N00B_TESTS='rocs_service_smoke' \
bash ./build.sh /private/tmp/n00b_rocs_service_local
```

Run the reference binary against the service-local profile:

```sh
ROCS_PROFILE=service_local \
ROCS_HTTP_ADDR=127.0.0.1:8080 \
ROCS_READ_ONLY=false \
ROCS_WRITER_MODE=single_writer \
/private/tmp/n00b_rocs_service_local/n00b-rocs-service --serve
```

In another shell:

```sh
curl -sS http://127.0.0.1:8080/healthz/startup
curl -sS http://127.0.0.1:8080/healthz/ready
curl -sS http://127.0.0.1:8080/healthz/live
curl -sS -X POST http://127.0.0.1:8080/v1/records \
  -H 'content-type: application/json' \
  -d '{"id":1}'
curl -sS -X POST http://127.0.0.1:8080/v1/query \
  -H 'content-type: application/json' \
  -d '{"filter":{"exists":"id"},"limit":10}'
```

The public runtime API accepts a caller-supplied schema. The standalone
reference binary uses its built-in minimal schema for smoke and packaging
paths; `ROCS_SCHEMA` is preserved as deployment/config metadata for the service
profile and for applications embedding `n00b_rocs_service_start`.

## Kubernetes JSON path

Build or publish an image from the repository root:

```sh
docker build -f docker/rocs-service.Dockerfile -t rocs-service:latest .
```

Edit `deploy/rocs/rocs-service.json` before applying it:

- replace `replace-with-bucket` with the durable S3 bucket
- replace `rocs/prod` with the object-prefix root for this deployment
- replace the ServiceAccount workload-identity role placeholder
- replace the schema Secret value if your application embeds a different schema
- replace `rocs-service:latest` with your registry image if needed

Apply the JSON manifest:

```sh
kubectl apply -f deploy/rocs/rocs-service.json
```

The manifest is a Kubernetes `List` containing:

- `ServiceAccount` with an EKS workload-identity annotation placeholder
- `ConfigMap` for non-sensitive rocs service defaults
- `Secret` carrying the schema metadata value
- one `rocs-writer` Deployment with `ROCS_WRITER_MODE=single_writer`
- one `rocs-reader` Deployment with `ROCS_READ_ONLY=true` and
  `ROCS_WRITER_MODE=read_replica`
- separate writer and reader Services
- a reader PodDisruptionBudget

## Credentials

Cloud credentials must come from the runtime credential chain. On EKS, use
workload identity by binding the `rocs-service` ServiceAccount to an IAM role
with IRSA or EKS Pod Identity and grant access to the configured bucket/prefix.
Do not put long-lived cloud credential values in the JSON manifest, image,
ConfigMap, Secret, tests, or examples.

## Health and metrics

The service exposes:

- startup: `/healthz/startup`
- readiness: `/healthz/ready`
- liveness: `/healthz/live`
- metrics: `/metrics`

Startup is green only after config, schema, store open, route registration, and
listener startup. Readiness is green only when the service can safely serve
traffic: not draining, dependency-ready, and store-open. Liveness stays green
while the process/runtime is alive, including dependency outage or draining
states. During graceful shutdown, make readiness red first, let traffic drain,
then stop the runtime so store close can release resident pins.

Prometheus scrape annotations in `rocs-service.json` target `/metrics`.
Reported metrics include service readiness/up state, resident bytes/shards,
active pins, catalog generation and entries, VFS/S3 error counters, cache
hit/miss counters, request/error/latency counters, unload counters, and live
queue pressure where the service owns live adapters.

## Cache and residency

The JSON example mounts an `emptyDir` cache at `/var/cache/rocs` and sets:

- `ROCS_CACHE_DIR=/var/cache/rocs`
- `ROCS_CACHE_BYTES=1073741824`
- `ROCS_RESIDENT_BYTES=536870912`
- `ROCS_RESIDENT_SHARDS=128`

If the cache volume or cache directory is removed, rocs still uses pinned-buffer
residency for object-store shard bodies. It does not claim direct mmap for S3 or
other object-store shards. Direct cache-file mmap remains out of scope until the
VFS layer exposes a stable materialized-path contract.

Default cache/resident budgets are bounded. When platform/cgroup limits are
available, profile defaults derive conservative limits from them; otherwise
they fall back to fixed conservative values. Tune the manifest resource requests,
limits, and rocs cache/resident env values together.

## Common failure modes

- **S3 outage:** startup may fail if the configured backend cannot be opened.
  A running service should keep liveness green while readiness is false when a
  supervisor marks the dependency unavailable; watch the VFS/S3 error counter.
- **Catalog unavailable:** startup or readiness should fail before traffic is
  served. Do not route writes to a pod that is not ready.
- **Retention boundary:** clients resuming from stale retained positions must
  restart from the store-reported oldest available boundary; sealed shards are
  never rewritten or unmarshaled to repair old positions.
- **Cache full:** reduce cache pressure by lowering read concurrency, increasing
  the cache volume/limit, or lowering resident shard/byte budgets. The fallback
  residency model remains pinned-buffer based.
- **Memory pressure:** resident bytes, resident shard count, active pins, and
  unload counters show whether query/result lifetimes are holding memory. Stop
  closes finite query results before store close; leaked pins make close fail.
- **Read-only replica mutation:** `POST /v1/records` returns a deterministic
  read-only rejection on reader pods. Send writes to the writer Service.

## Optional S3 smoke

The mandatory repository smoke uses the local profile and requires no cloud
backend. An opt-in LocalStack/S3 smoke mode exists in
`test_rocs_service_smoke`; it skips with exit 77 when endpoint or bucket
environment is absent or the backend is clearly unavailable. Credential material
must come from the normal external credential chain; the optional smoke does not
create fallback key material.
