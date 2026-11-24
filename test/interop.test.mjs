/**
 * Cross-language interop proof.
 *  (1) TypeScript verifies a bundle the PYTHON reference signed (offline).
 *  (2) TypeScript rebuilds the SAME bundle from the same key/instant and asserts
 *      byte-for-byte equality (Ed25519 is deterministic: identical JCS bytes ->
 *      identical signature), then writes it for Python to verify in reverse.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync, writeFileSync, mkdtempSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { fileURLToPath } from "node:url";
import { dirname } from "node:path";

import { canonicalise, ref } from "../dist/jcs.js";
import { mandateRef, guardrailRef } from "../dist/l1.js";
import * as keys from "../dist/keys.js";
import { parse } from "../dist/time.js";
import { makeIntent, approve, verifyApproval } from "../dist/intent.js";
import { issueMandate, revoke, verifyMandate, mandateBody } from "../dist/mandate.js";
import { Ledger } from "../dist/ledger.js";
import { Guard, policyBoundRef } from "../dist/guard.js";
import { bindSettlement } from "../dist/receipt.js";
import { verifyDecision, verifySettlement } from "../dist/verify.js";

const here = dirname(fileURLToPath(import.meta.url));
const py = JSON.parse(readFileSync(join(here, "fixtures", "py_fixtures.json"), "utf8"));
const now = parse(py.now);

test("TS verifies the Python-signed mandate (Ed25519 + frozen L1 ref)", () => {
  const [ok, reasons] = verifyMandate(py.envelope, now);
  assert.equal(ok, true, reasons.join("; "));
  assert.equal(
    mandateRef(py.envelope.payer, py.envelope.cap, py.envelope.period, py.envelope.revocation_state),
    py.envelope.mandate_ref,
  );
  // Direct cross-language signature check over the JCS envelope body.
  assert.equal(
    keys.verify(py.human_pub, canonicalise(mandateBody(py.envelope)), py.envelope.sig),
    true,
  );
});

test("TS recomputes the Python policy/guardrail refs", () => {
  assert.equal(policyBoundRef(py.envelope), py.policy_ref);
  assert.equal(guardrailRef(py.agent_ref, py.envelope.mandate_ref, py.policy_ref, "ALLOW"), py.allow_ref);
});

test("TS verifies the Python human countersign", () => {
  const [ok, reasons] = verifyApproval(py.approval_allow, py.allow_ref, py.intent_allow, py.human_pub, now);
  assert.equal(ok, true, reasons.join("; "));
});

test("TS verifies the Python ALLOW decision receipt offline (with ledger)", () => {
  const [ok, reasons] = verifyDecision(py.envelope, py.receipt_allow, py.ledger_snapshot);
  assert.equal(ok, true, reasons.join("; "));
});

test("TS verifies the Python DENY decision receipt offline", () => {
  const [ok, reasons] = verifyDecision(py.envelope, py.receipt_deny, py.ledger_snapshot);
  assert.equal(ok, true, reasons.join("; "));
  assert.equal(py.receipt_deny.verdict, "DENY");
});

test("TS verifies the Python settlement binding offline", () => {
  const [ok, reasons] = verifySettlement(py.envelope, py.receipt_allow, py.settlement, py.ledger_snapshot);
  assert.equal(ok, true, reasons.join("; "));
});

test("TS refuses the Python revoked mandate", () => {
  const [ok, reasons] = verifyMandate(py.revoked_envelope, now);
  assert.equal(ok, false);
  assert.ok(reasons.some((r) => r.includes("revoked")));
});

test("TS rebuilds the identical bundle (byte-for-byte) and writes it for Python", () => {
  const PRIV = py.human_priv;
  const env = issueMandate({
    payer: py.envelope.payer, cap: py.envelope.cap, humanPriv: PRIV,
    period: py.envelope.period, payee: "*", maxPerCharge: py.envelope.max_per_charge, now,
  });
  assert.deepStrictEqual(env, py.envelope, "TS envelope != Python envelope");

  const agentRef = ref({ type: "agent", id: "demo-agent" });
  assert.equal(agentRef, py.agent_ref);
  const policyRef = policyBoundRef(env);
  const allowRef = guardrailRef(agentRef, env.mandate_ref, policyRef, "ALLOW");

  const i1 = makeIntent({
    chargeId: "charge-001", mandateRef: env.mandate_ref, payee: "merchant-a",
    amount: 400, asset: "USDC", at: now,
  });
  assert.deepStrictEqual(i1, py.intent_allow, "TS intent != Python intent");
  const a1 = approve(allowRef, i1, PRIV, py.expires_at);
  assert.deepStrictEqual(a1, py.approval_allow, "TS countersign != Python countersign");

  const dir = mkdtempSync(join(tmpdir(), "guard-interop-"));
  try {
    const led = new Ledger(join(dir, "ledger.jsonl"));
    const g = new Guard(env, led, agentRef, () => now);
    const rAllow = g.decide(i1, a1);
    assert.deepStrictEqual(rAllow, py.receipt_allow, "TS ALLOW receipt != Python receipt");
    const snap = led.snapshot();
    assert.deepStrictEqual(snap, py.ledger_snapshot, "TS ledger snapshot != Python snapshot");

    const i2 = makeIntent({
      chargeId: "charge-002", mandateRef: env.mandate_ref, payee: "merchant-a",
      amount: 700, asset: "USDC", at: now,
    });
    const a2 = approve(allowRef, i2, PRIV, py.expires_at);
    const rDeny = g.decide(i2, a2);
    assert.deepStrictEqual(rDeny, py.receipt_deny, "TS DENY receipt != Python receipt");

    const settlement = bindSettlement(rAllow, "tx:0xabc123");
    assert.deepStrictEqual(settlement, py.settlement, "TS settlement != Python settlement");
    const revoked = revoke(env, PRIV);
    assert.deepStrictEqual(revoked, py.revoked_envelope, "TS revoked != Python revoked");

    const bundle = {
      human_priv: PRIV, human_pub: keys.pubFromPriv(PRIV), kid: keys.kidFor(keys.pubFromPriv(PRIV)),
      now: py.now, expires_at: py.expires_at, agent_ref: agentRef,
      policy_ref: policyRef, allow_ref: allowRef,
      envelope: env, intent_allow: i1, approval_allow: a1,
      receipt_allow: rAllow, ledger_snapshot: snap,
      intent_deny: i2, approval_deny: a2, receipt_deny: rDeny,
      settlement, revoked_envelope: revoked,
    };
    writeFileSync(join(here, "fixtures", "ts_fixtures.json"), JSON.stringify(bundle, null, 2));
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
