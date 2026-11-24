/** Guard decision matrix + tamper refusal, mirroring the Python reference suite. */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { Buffer } from "node:buffer";

import { canonicalise, ref, JcsError } from "../dist/jcs.js";
import { guardrailRef } from "../dist/l1.js";
import * as keys from "../dist/keys.js";
import { iso, parse } from "../dist/time.js";
import { makeIntent, approve, approvalText, verifyApproval } from "../dist/intent.js";
import { issueMandate, revoke } from "../dist/mandate.js";
import { Ledger, verifyChain } from "../dist/ledger.js";
import { Guard, policyBoundRef } from "../dist/guard.js";
import { verifyDecision } from "../dist/verify.js";

// Fixed deterministic key (bytes 0..31), same as the interop fixture.
const FIXED_PRIV = Buffer.from(Array.from({ length: 32 }, (_, i) => i)).toString("base64url");
const NOW = parse("2026-11-24T03:00:00Z");
const EXPIRES = "2026-11-24T04:00:00Z";
const AGENT = ref({ type: "agent", id: "matrix-agent" });

function setup(opts = {}) {
  const env = issueMandate({
    payer: "0x00000000000000000000000000000000DEADBEEF",
    cap: opts.cap ?? "1000", humanPriv: FIXED_PRIV, period: "monthly",
    payee: opts.payee ?? "*", maxPerCharge: opts.maxPerCharge ?? "600",
    scope: opts.scope ?? null, now: NOW, ttlSecs: opts.ttlSecs ?? 31_536_000,
  });
  const dir = mkdtempSync(join(tmpdir(), "guard-matrix-"));
  const led = new Ledger(join(dir, "ledger.jsonl"));
  const g = new Guard(env, led, AGENT, () => NOW);
  const policy = policyBoundRef(env);
  const allow = guardrailRef(AGENT, env.mandate_ref, policy, "ALLOW");
  return { env, led, g, policy, allow, cleanup: () => rmSync(dir, { recursive: true, force: true }) };
}

function intentFor(s, chargeId, amount, extra = {}) {
  return makeIntent({
    chargeId, mandateRef: s.env.mandate_ref, payee: extra.payee ?? "merchant-a",
    amount, asset: "USDC", at: NOW, scope: extra.scope ?? null,
  });
}

test("ALLOW happy path commits exactly once", () => {
  const s = setup();
  try {
    const i = intentFor(s, "c1", 400);
    const r = s.g.decide(i, approve(s.allow, i, FIXED_PRIV, EXPIRES));
    assert.equal(r.verdict, "ALLOW");
    assert.equal(s.led.entries.length, 1);
    const [ok, reasons] = verifyDecision(s.env, r, s.led.snapshot());
    assert.equal(ok, true, reasons.join("; "));
  } finally { s.cleanup(); }
});

test("per-charge cap boundary: == max ALLOW, +1 DENY", () => {
  const s = setup({ maxPerCharge: "600" });
  try {
    const i600 = intentFor(s, "c600", 600);
    assert.equal(s.g.decide(i600, approve(s.allow, i600, FIXED_PRIV, EXPIRES)).verdict, "ALLOW");
    const i601 = intentFor(s, "c601", 601);
    const r601 = s.g.decide(i601, approve(s.allow, i601, FIXED_PRIV, EXPIRES));
    assert.equal(r601.verdict, "DENY");
    assert.ok(r601.reasons.includes("policy: per_charge_cap"));
  } finally { s.cleanup(); }
});

test("period cap: cumulative spend cannot exceed cap", () => {
  const s = setup({ cap: "1000", maxPerCharge: "600" });
  try {
    const i1 = intentFor(s, "p1", 600);
    assert.equal(s.g.decide(i1, approve(s.allow, i1, FIXED_PRIV, EXPIRES)).verdict, "ALLOW");
    const i2 = intentFor(s, "p2", 400);
    assert.equal(s.g.decide(i2, approve(s.allow, i2, FIXED_PRIV, EXPIRES)).verdict, "ALLOW");
    const i3 = intentFor(s, "p3", 1);
    const r3 = s.g.decide(i3, approve(s.allow, i3, FIXED_PRIV, EXPIRES));
    assert.equal(r3.verdict, "DENY");
    assert.ok(r3.reasons.includes("policy: period_cap"));
  } finally { s.cleanup(); }
});

test("replay: same charge_id refused after commit", () => {
  const s = setup();
  try {
    const i = intentFor(s, "dup", 400);
    const a = approve(s.allow, i, FIXED_PRIV, EXPIRES);
    assert.equal(s.g.decide(i, a).verdict, "ALLOW");
    const r2 = s.g.decide(i, a);
    assert.equal(r2.verdict, "DENY");
    assert.ok(r2.reasons.includes("policy: replay"));
    assert.equal(s.led.entries.length, 1);
  } finally { s.cleanup(); }
});

test("payee not allowed", () => {
  const s = setup({ payee: "merchant-a" });
  try {
    const i = intentFor(s, "pay1", 400, { payee: "merchant-b" });
    const r = s.g.decide(i, approve(s.allow, i, FIXED_PRIV, EXPIRES));
    assert.equal(r.verdict, "DENY");
    assert.ok(r.reasons.includes("policy: payee_not_allowed"));
  } finally { s.cleanup(); }
});

test("scope not allowed", () => {
  const s = setup({ scope: ["inference"] });
  try {
    const i = intentFor(s, "sc1", 400, { scope: "training" });
    const r = s.g.decide(i, approve(s.allow, i, FIXED_PRIV, EXPIRES));
    assert.equal(r.verdict, "DENY");
    assert.ok(r.reasons.includes("policy: scope_not_allowed"));
  } finally { s.cleanup(); }
});

test("countersign required", () => {
  const s = setup();
  try {
    const r = s.g.decide(intentFor(s, "nc1", 400), null);
    assert.equal(r.verdict, "DENY");
    assert.ok(r.reasons.includes("countersign: required"));
  } finally { s.cleanup(); }
});

test("countersign under a different key is refused", () => {
  const s = setup();
  try {
    const i = intentFor(s, "fk1", 400);
    const otherPriv = Buffer.from(Array.from({ length: 32 }, (_, k) => k + 1)).toString("base64url");
    const r = s.g.decide(i, approve(s.allow, i, otherPriv, EXPIRES));
    assert.equal(r.verdict, "DENY");
    assert.ok(r.reasons.some((x) => x.startsWith("countersign: key:")));
  } finally { s.cleanup(); }
});

test("stale countersign (expired) is refused", () => {
  const s = setup();
  try {
    const i = intentFor(s, "st1", 400);
    const a = approve(s.allow, i, FIXED_PRIV, "2026-11-24T02:00:00Z");
    const r = s.g.decide(i, a);
    assert.equal(r.verdict, "DENY");
    assert.ok(r.reasons.some((x) => x.includes("expired")));
  } finally { s.cleanup(); }
});

test("countersign display-text tamper is refused", () => {
  const s = setup();
  try {
    const i = intentFor(s, "tx1", 400);
    const a = approve(s.allow, i, FIXED_PRIV, EXPIRES);
    a.approval_text = approvalText(s.allow, i, EXPIRES).replace("400", "4");
    const [ok, reasons] = verifyApproval(a, s.allow, i, keys.pubFromPriv(FIXED_PRIV), NOW);
    assert.equal(ok, false);
    assert.ok(reasons.some((x) => x.startsWith("text:")));
  } finally { s.cleanup(); }
});

test("revoked mandate denies", () => {
  const s = setup();
  try {
    const rev = revoke(s.env, FIXED_PRIV);
    s.g.setEnvelope(rev);
    const i = makeIntent({ chargeId: "rv1", mandateRef: rev.mandate_ref, payee: "merchant-a", amount: 400, at: NOW });
    const allowRev = guardrailRef(AGENT, rev.mandate_ref, policyBoundRef(rev), "ALLOW");
    const r = s.g.decide(i, approve(allowRev, i, FIXED_PRIV, EXPIRES));
    assert.equal(r.verdict, "DENY");
    assert.ok(r.reasons.some((x) => x.includes("revoked")));
  } finally { s.cleanup(); }
});

test("hostile intent (float amount) -> DENY, never raises", () => {
  const s = setup();
  try {
    const bad = { type: "charge_intent", version: "1", charge_id: "h1", mandate_ref: s.env.mandate_ref,
      payee: "merchant-a", amount: 400.5, asset: "USDC", at: iso(NOW), settlement_ref: null, scope: null };
    const r = s.g.decide(bad, null);
    assert.equal(r.verdict, "DENY");
    assert.ok(r.reasons.some((x) => x.startsWith("intent:")));
  } finally { s.cleanup(); }
});

test("hostile intent (missing fields) -> DENY, never raises", () => {
  const s = setup();
  try {
    assert.equal(s.g.decide({ charge_id: "h2" }, null).verdict, "DENY");
  } finally { s.cleanup(); }
});

test("receipt verdict tamper is refused offline", () => {
  const s = setup();
  try {
    const i = intentFor(s, "vt1", 400);
    const r = s.g.decide(i, approve(s.allow, i, FIXED_PRIV, EXPIRES));
    const snap = s.led.snapshot();
    const tampered = { ...r, verdict: "DENY", guardrail_ref: guardrailRef(AGENT, s.env.mandate_ref, s.policy, "DENY") };
    const [ok, reasons] = verifyDecision(s.env, tampered, snap);
    assert.equal(ok, false);
    assert.ok(reasons.length > 0);
  } finally { s.cleanup(); }
});

test("receipt amount tamper is refused offline", () => {
  const s = setup();
  try {
    const i = intentFor(s, "at1", 400);
    const r = s.g.decide(i, approve(s.allow, i, FIXED_PRIV, EXPIRES));
    const snap = s.led.snapshot();
    const tampered = { ...r, intent: { ...r.intent, amount: 4 } };
    assert.equal(verifyDecision(s.env, tampered, snap)[0], false);
  } finally { s.cleanup(); }
});

test("ledger chain tamper is detected offline", () => {
  const s = setup();
  try {
    const i1 = intentFor(s, "l1", 400);
    s.g.decide(i1, approve(s.allow, i1, FIXED_PRIV, EXPIRES));
    const i2 = intentFor(s, "l2", 100);
    s.g.decide(i2, approve(s.allow, i2, FIXED_PRIV, EXPIRES));
    const snap = s.led.snapshot();
    assert.equal(verifyChain(snap.entries)[0], true);
    const entries = structuredClone(snap.entries);
    entries[0].amount = 999;
    const [ok, reasons] = verifyChain(entries);
    assert.equal(ok, false);
    assert.ok(reasons.length > 0);
  } finally { s.cleanup(); }
});

test("BigInt amount (safe range) ALLOW commits and verifies, incl. after reload", () => {
  const s = setup();
  try {
    const i = intentFor(s, "big-ok", 400n);
    const r = s.g.decide(i, approve(s.allow, i, FIXED_PRIV, EXPIRES));
    assert.equal(r.verdict, "ALLOW");
    assert.equal(verifyDecision(s.env, r, s.led.snapshot())[0], true);
    // Reload the ledger from disk (BigInt stored as an exact Number token).
    const reloaded = new Ledger(s.led.path);
    assert.equal(verifyChain(reloaded.entries)[0], true);
    assert.equal(verifyDecision(s.env, r, reloaded.snapshot())[0], true);
  } finally { s.cleanup(); }
});

test("BigInt amount beyond safe integer range DENYs fail-closed, never throws", () => {
  const s = setup({ cap: "100000000000000000000", maxPerCharge: "100000000000000000000" });
  try {
    const huge = BigInt(Number.MAX_SAFE_INTEGER) + 2n;
    const i = intentFor(s, "big-unsafe", huge);
    const r = s.g.decide(i, approve(s.allow, i, FIXED_PRIV, EXPIRES));
    assert.equal(r.verdict, "DENY");
    assert.ok(r.reasons.some((x) => x.startsWith("ledger:")));
    assert.equal(s.led.entries.length, 0);
  } finally { s.cleanup(); }
});

test("JCS rejects non-integers and lone surrogates", () => {
  assert.throws(() => canonicalise({ k: 2.5 }), JcsError);
  assert.throws(() => canonicalise("a\ud800b"), JcsError);
});

test("JCS key ordering is UTF-16 code-unit (RFC 8785 3.2.3)", () => {
  const out = new TextDecoder().decode(canonicalise({ "\u{10000}": 1, "\uFFFF": 2, a: 3 }));
  const ia = out.indexOf('"a"');
  const iff = out.indexOf('"\uFFFF"');
  const i10000 = out.indexOf('"\u{10000}"');
  assert.ok(ia >= 0 && iff >= 0 && i10000 >= 0, out);
  // UTF-16 code units: U+10000 -> [D800,DC00] sorts BEFORE U+FFFF -> [FFFF].
  assert.ok(ia < i10000 && i10000 < iff, `order wrong: ${out}`);
});
