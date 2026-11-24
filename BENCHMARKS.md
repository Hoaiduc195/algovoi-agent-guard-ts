# Benchmarks

Measured with `performance.now()` (no mocks), regenerated from `bench.json` via `tools/bench.mjs` + `tools/gen_benchmarks.mjs`.

Runtime: Node v22.23.5 on linux; Ed25519 via @noble/curves ed25519 (pure JS, no native deps).

> Pure-JS Ed25519 is slower than a native crypto backend; each decision verifies two
> signatures (mandate + countersign). Auditability and offline recomputability are
> favoured over throughput. These figures are from this run's own log, not a target.

## Hot paths

| Path | n | ops/s | median | p95 |
|---|---|---|---|---|
| evaluate() (pure) | 3000 | 198 | 4.58 ms | 7.81 ms |
| verifyDecision() (offline) | 3000 | 211.9 | 4.53 ms | 5.74 ms |
| decide() ALLOW + commit | 200 | 93.5 | 10.57 ms | 15.47 ms |

## Append latency vs ledger size (full-history rewrite + fsync)

| entries | n | ops/s | median | p95 |
|---|---|---|---|---|
| 0 | 20 | 730.7 | 1.38 ms | 2.11 ms |
| 100 | 20 | 218.9 | 4.22 ms | 6.89 ms |
| 300 | 20 | 97.4 | 10.22 ms | 11.21 ms |
| 500 | 20 | 54.9 | 18.28 ms | 19.85 ms |

## Hash-chain verify vs ledger size

| entries | n | ops/s | median | p95 |
|---|---|---|---|---|
| 100 | 15 | 330.5 | 2.94 ms | 3.96 ms |
| 300 | 15 | 121.4 | 8.14 ms | 9.58 ms |
| 500 | 15 | 63.7 | 15.72 ms | 16.90 ms |
| 1000 | 15 | 34.2 | 28.21 ms | 36.48 ms |

## Tamper detection vs ledger size (one mutated mid-chain entry)

| entries | n | ops/s | median | p95 | detected |
|---|---|---|---|---|---|
| 100 | 15 | 322.7 | 2.62 ms | 4.85 ms | true |
| 500 | 15 | 72 | 13.54 ms | 16.11 ms | true |
| 1000 | 15 | 30 | 31.36 ms | 49.29 ms | true |

Every injected mid-chain mutation is detected (`detected: true`).
