# Fork milestones

This roadmap tracks the compfaculty fork, which starts from upstream 0.14.1. The [changelog](CHANGELOG.md) records changes available in the checkout.

## 1. Establish the fork baseline

- [x] Document the build, workspace, and request flow in the [README](README.md).
- [x] Cover startup errors, rejected reloads, accepted reloads, and listener bind failures with process-level regression tests.
- [ ] Confirm the Linux CI matrix passes for the default Quinn build, a TCP-only build, and the s2n-quic build.
- [x] Verify multi-domain TLS, distinct upstreams, and client authentication across the three local builds. The [acceptance test](rpxy-bin/tests/lifecycle/tls.rs) covers HTTP/1.1 and HTTP/2 in every build and HTTP/3 in both QUIC builds.
- [ ] Record a repeatable performance baseline using the [benchmark harness](bench/README.md). Measure throughput, tail latency, CPU, and memory across HTTP/1.1, HTTP/2, and HTTP/3. Include TLS handshakes and steady-state connection reuse.

## 2. Make configuration changes safer to deploy

- [x] Add a `--check-config` command for CI and deployment scripts. It validates routes, static TLS materials, and feature settings without binding listeners or contacting ACME.
- [ ] Add rollback for reload failures discovered during listener startup. Cover occupied TCP and UDP ports, invalid certificates, and rapid successive edits.
- [ ] Define how existing connections drain on reload and shutdown. Verify connection reuse, long-lived streams, and the transition between connection limits in successive generations.
- [ ] Finish HTTP/3 stream error handling for late request length mismatches. Add coverage with an early-responding local upstream.

## 3. Add operations features

- [ ] Expose opt-in metrics for request latency and status, active connections, upstream health, and reload outcomes. Bound label cardinality to configured apps and routes, and avoid labeling with client-supplied hostnames or paths. Evaluate OpenTelemetry export once the metrics are stable.
- [ ] Make sticky-cookie name and lifetime configurable per route. Preserve existing deployments with compatible defaults.
- [ ] Evaluate serving complete client certificate chains and supporting per-domain client authentication over HTTP/3. Keep client-authentication domains off HTTP/3 until the QUIC path can enforce the same policy as TCP.

## Backlog

- More flexible path rewrites and custom HTTP error pages.
- A radix or trie matcher if profiling shows that the current longest-prefix scan dominates at realistic route counts.
- Persistent caching and changes to the in-memory LRU if measured workloads justify the operational cost.
- Expand configuration reference and tests as fork features are added.
