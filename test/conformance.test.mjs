// Conformance gate: the TypeScript port must reproduce the estate's frozen L1
// spend-authority refs byte-for-byte from the SAME public vector files the
// Python package gates on. Every expected ref, every negative recomputation and
// every rejection is asserted. Plus an RFC 8785 3.2.3 UTF-16 key-ordering probe.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { canonicalise, ref, JcsError } from "../dist/jcs.js";
import { mandateRef, guardrailRef, L1Error } from "../dist/l1.js";

const here = dirname(fileURLToPath(import.meta.url));
const load = (n) => JSON.parse(readFileSync(join(here, "vectors", n), "utf8"));

const pm = load("payment_mandate_lite_v1.json");
const sg = load("spend_guardrail_lite_v1.json");

test("payment_mandate_lite: every positive vector recomputes its expected ref", () => {
  for (const v of pm.vectors) {
    const got = mandateRef(v.payer, v.cap, v.period, v.revocation_state);
    assert.equal(got, v.expected_mandate_ref, `${v.id}`);
  }
});

test("payment_mandate_lite: every 'differ' negative recomputes to its stated ref and diverges from the claim", () => {
  for (const n of pm.negatives.filter((x) => x.must === "differ")) {
    const got = mandateRef(n.payer, n.cap, n.period, n.revocation_state);
    assert.equal(got, n.recomputes_to, `${n.id} recompute`);
    assert.notEqual(got, n.claimed_mandate_ref, `${n.id} diverges`);
  }
});

test("payment_mandate_lite: every 'reject' negative is rejected, not hashed", () => {
  for (const n of pm.negatives.filter((x) => x.must === "reject")) {
    assert.throws(
      () => mandateRef(n.payer, n.cap, n.period, n.revocation_state),
      L1Error,
      `${n.id}`,
    );
  }
});

test("spend_guardrail_lite: every positive vector recomputes its expected ref", () => {
  for (const v of sg.vectors) {
    const got = guardrailRef(v.agent_ref, v.mandate_ref, v.policy_bound_ref, v.verdict);
    assert.equal(got, v.expected_guardrail_ref, `${v.id}`);
  }
});

test("spend_guardrail_lite: every 'differ' negative recomputes and diverges", () => {
  for (const n of sg.negatives.filter((x) => x.must === "differ")) {
    const got = guardrailRef(n.agent_ref, n.mandate_ref, n.policy_bound_ref, n.verdict);
    assert.equal(got, n.recomputes_to, `${n.id} recompute`);
    assert.notEqual(got, n.claimed_guardrail_ref, `${n.id} diverges`);
  }
});

test("spend_guardrail_lite: every 'reject' negative is rejected, not hashed", () => {
  for (const n of sg.negatives.filter((x) => x.must === "reject")) {
    assert.throws(
      () => guardrailRef(n.agent_ref, n.mandate_ref, n.policy_bound_ref, n.verdict),
      L1Error,
      `${n.id}`,
    );
  }
});

test("cross-set continuity: mandate_1/mandate_2 equal the payment_mandate pm-001/pm-002 refs", () => {
  assert.equal(sg.mandates.mandate_1, pm.vectors[0].expected_mandate_ref);
  assert.equal(sg.mandates.mandate_2, pm.vectors[1].expected_mandate_ref);
});

test("RFC 8785 3.2.3: keys sort by UTF-16 code units (supplementary plane before U+FB33)", () => {
  // U+10000 is a surrogate pair (D800 DC00); its first code unit D800 < FB33,
  // so it sorts BEFORE U+FB33 even though its code point (65536) is larger.
  const obj = { "\uFB33": 1, "\u{10000}": 2 };
  const bytes = canonicalise(obj);
  const text = new TextDecoder().decode(bytes);
  assert.equal(text, '{"\u{10000}":2,"\uFB33":1}');
});

test("JCS string escaping matches the JSON mandatory set", () => {
  const s = 'a"b\\c\bd\te\nf\fg\rh\u0001i';
  const text = new TextDecoder().decode(canonicalise(s));
  assert.equal(text, '"a\\"b\\\\c\\bd\\te\\nf\\fg\\rh\\u0001i"');
});

test("JCS rejects floats and lone surrogates", () => {
  assert.throws(() => canonicalise(1.5), JcsError);
  assert.throws(() => canonicalise("a\ud800b"), JcsError); // lone high surrogate
  assert.throws(() => canonicalise({ k: 2.5 }), JcsError); // non-integer in object
});

test("JCS integer and BigInt serialisation", () => {
  assert.equal(new TextDecoder().decode(canonicalise(1000)), "1000");
  assert.equal(new TextDecoder().decode(canonicalise(-5)), "-5");
  assert.equal(new TextDecoder().decode(canonicalise(10n ** 30n)), "1" + "0".repeat(30));
});
