/** Measured benchmarks for algovoi-agent-guard-ts (real performance.now, no mocks). */
import { performance } from "node:perf_hooks";
import { mkdirSync, rmSync, existsSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { Buffer } from "node:buffer";

import { guardrailRef } from "../dist/l1.js";
import { ref } from "../dist/jcs.js";
import * as keys from "../dist/keys.js";
import { parse } from "../dist/time.js";
import { makeIntent, approve } from "../dist/intent.js";
import { issueMandate } from "../dist/mandate.js";
import { Ledger, verifyChain } from "../dist/ledger.js";
import { Guard, policyBoundRef, evaluate } from "../dist/guard.js";
import { verifyDecision } from "../dist/verify.js";

const OUT = process.argv[2] ?? join(tmpdir(), "mg-ts-bench");
mkdirSync(OUT, { recursive: true });
const PRIV = Buffer.from(Array.from({ length: 32 }, (_, i) => i)).toString("base64url");
const NOW = parse("2026-11-23T08:00:00Z");
const AGENT = "sha256:" + "b3".repeat(32);
const EXPIRES = "2026-11-23T09:00:00Z";
const TS = "2026-11-23T08:00:00Z";
const ENV = issueMandate({
  payer: "payer-1", cap: "100000000", period: "monthly", payee: "vendor-1",
  scope: ["inference"], maxPerCharge: "250", humanPriv: PRIV, now: NOW,
});
const POLICY = policyBoundRef(ENV);
const ALLOW = guardrailRef(AGENT, ENV.mandate_ref, POLICY, "ALLOW");

const mkIntent = (cid, amount = 100) =>
  makeIntent({ chargeId: cid, mandateRef: ENV.mandate_ref, payee: "vendor-1", amount, at: NOW, scope: "inference" });
const approveI = (i) => approve(ALLOW, i, PRIV, EXPIRES);

function stats(samples) {
  const s = [...samples].sort((a, b) => a - b);
  const n = s.length;
  const sum = s.reduce((a, b) => a + b, 0);
  return {
    n,
    ops_per_sec: sum ? Math.round((n / sum) * 10) / 10 : null,
    median_us: Math.round(s[Math.floor(n / 2)] * 1e6 * 10) / 10,
    p95_us: Math.round(s[Math.min(n - 1, Math.floor(n * 0.95))] * 1e6 * 10) / 10,
    min_us: Math.round(s[0] * 1e6 * 10) / 10,
    max_us: Math.round(s[n - 1] * 1e6 * 10) / 10,
  };
}
function timeit(fn, n, warmup = 20) {
  for (let k = 0; k < warmup; k++) fn();
  const samples = [];
  for (let k = 0; k < n; k++) {
    const t = performance.now();
    fn();
    samples.push((performance.now() - t) / 1000);
  }
  return stats(samples);
}
const fresh = (name) => {
  const p = join(OUT, name);
  if (existsSync(p)) rmSync(p);
  return p;
};

const results = { node: process.version, platform: process.platform, crypto: "@noble/curves ed25519" };

// 1. pure evaluate
const i0 = mkIntent("eval");
const a0 = approveI(i0);
results.evaluate_pure = timeit(() => evaluate(ENV, i0, a0, [], AGENT, NOW), 3000);

// 2. offline verify_decision on a committed ALLOW receipt
const lv = new Ledger(fresh("bv.jsonl"));
const gv = new Guard(ENV, lv, AGENT, () => NOW);
const iv = mkIntent("verify-1");
const rv = gv.decide(iv, approveI(iv));
const snapV = lv.snapshot();
results.verify_decision_offline = timeit(() => verifyDecision(ENV, rv, snapV), 3000);

// 3. decide ALLOW + atomic commit (growing ledger)
const ld = new Ledger(fresh("bd.jsonl"));
const gd = new Guard(ENV, ld, AGENT, () => NOW);
let dk = 0;
results.decide_allow_commit_n200 = timeit(() => {
  const i = mkIntent(`d${dk++}`);
  gd.decide(i, approveI(i));
}, 200, 10);

// 4. single-append latency vs ledger size
const appendScaling = {};
for (const size of [0, 100, 300, 500]) {
  const lg = new Ledger(fresh(`app${size}.jsonl`));
  for (let k = 0; k < size; k++)
    lg.append({ chargeId: `s${k}`, amount: 10, asset: "USDC", payee: "vendor-1", period: "monthly", guardrailRef: ALLOW, ts: TS });
  let xk = 0;
  appendScaling[size] = timeit(() => {
    lg.append({ chargeId: `x${size}_${xk++}`, amount: 10, asset: "USDC", payee: "vendor-1", period: "monthly", guardrailRef: ALLOW, ts: TS });
  }, 20, 3);
}
results.append_latency_by_ledger_size = appendScaling;

// 5. verify_chain latency vs ledger size
const chainScaling = {};
for (const size of [100, 300, 500, 1000]) {
  const lg = new Ledger(fresh(`chain${size}.jsonl`));
  for (let k = 0; k < size; k++)
    lg.append({ chargeId: `c${k}`, amount: 10, asset: "USDC", payee: "vendor-1", period: "monthly", guardrailRef: ALLOW, ts: TS });
  const entries = lg.entries;
  chainScaling[size] = timeit(() => verifyChain(entries), 15, 2);
}
results.verify_chain_by_ledger_size = chainScaling;

// 6. tamper-detection latency vs ledger size
const tamperScaling = {};
for (const size of [100, 500, 1000]) {
  const lg = new Ledger(fresh(`tam${size}.jsonl`));
  for (let k = 0; k < size; k++)
    lg.append({ chargeId: `t${k}`, amount: 10, asset: "USDC", payee: "vendor-1", period: "monthly", guardrailRef: ALLOW, ts: TS });
  const bad = structuredClone(lg.entries);
  bad[Math.floor(size / 2)].amount += 1;
  const det = timeit(() => verifyChain(bad), 15, 2);
  det.detected = !verifyChain(bad)[0];
  tamperScaling[size] = det;
}
results.tamper_detection_by_ledger_size = tamperScaling;

writeFileSync(join(OUT, "bench.json"), JSON.stringify(results, null, 2));
console.log(JSON.stringify(results, null, 2));
