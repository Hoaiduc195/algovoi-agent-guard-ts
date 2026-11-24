# AI and security disclaimer

`algovoi-agent-guard` (TypeScript) is a spend-authority enforcement and
verification library. Read this before using it.

## AI-assisted development

This implementation was built and cross-validated with AI assistance (large
language models used as builder and independent reviewers). AI output is
fallible. The cross-language conformance and interop results in this repository
are measured against the frozen public conformance vectors and the Python
reference implementation, **not** certified by a model's verdict. No model
approval is treated as a security guarantee.

## It moves no money and signs with no real key

The guard is an enforcement + verification layer. It **moves no funds**, holds no
real settlement credentials, and the tests and benchmarks sign with freshly
generated or fixed throwaway keys, never a production human key. Receipts are
canonical references for a settlement rail, not settlements.

## What the tests do and do not prove

- The frozen L1 refs, mandate envelopes, countersigns, decision receipts,
  settlement bindings and ledger chains are byte-conformant with the Python
  reference and the published conformance vectors, in both directions
  (Python signs / TypeScript verifies, and TypeScript signs / Python verifies).
- A zero-failure test run covers only the cases actually exercised. It is **not**
  a proof that the guard is secure, and it does not generalise to configurations,
  volumes or attack classes that were not run.
- The TypeScript port covers the core library (canonicalisation, frozen L1 refs,
  keys, intents/countersigns, mandates, ledger, guard, settlement, offline
  verify). The autonomous red-team engine and demo CLI are part of the Python
  reference and are **not** reimplemented here.

## No warranty

Provided "as is", without warranty of any kind, express or implied. See the
Apache-2.0 [`LICENSE`](LICENSE). Nothing here is financial, legal, or security
advice, and no production adoption or certified security audit is claimed.
