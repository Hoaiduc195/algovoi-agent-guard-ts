/**
 * Offline verification from public material only. No network, no secrets.
 *
 * verifyDecision() re-derives the verdict with the guard's own pure evaluate():
 * recomputes the frozen L1 refs and the policy ref, re-runs every check against
 * the envelope and (optionally) a ledger snapshot, and re-verifies the human
 * countersign for ALLOW. A receipt whose verdict or reasons do not recompute is
 * refused. verifySettlement() additionally checks the settlement binding covers
 * exactly the decision it claims.
 */
import { evaluate, policyBoundRef, type Envelope } from "./guard.js";
import { JcsError, ref } from "./jcs.js";
import { L1Error, VERDICTS, guardrailRef } from "./l1.js";
import { verifyChain, type Entry } from "./ledger.js";
import { parse } from "./time.js";

export function verifyDecision(
  envelope: Envelope,
  receipt: unknown,
  ledgerSnapshot?: Record<string, unknown> | null,
): [boolean, string[]] {
  const reasons: string[] = [];
  if (typeof receipt !== "object" || receipt === null || Array.isArray(receipt))
    return [false, ["schema: receipt must be an object"]];
  const r = receipt as Record<string, unknown>;
  const need = [
    "type", "version", "verdict", "guardrail_ref", "mandate_ref", "agent_ref",
    "policy_bound_ref", "intent", "reasons", "countersign", "ledger_head",
    "issued_at", "receipt_ref",
  ];
  const missing = need.filter((f) => !(f in r));
  if (missing.length) return [false, [`schema: missing fields ${JSON.stringify(missing)}`]];
  try {
    const { receipt_ref: _rr, ...body } = r;
    if (r.receipt_ref !== ref(body)) reasons.push("ref: receipt_ref does not recompute");
  } catch (exc) {
    if (exc instanceof JcsError) return [false, [`ref: receipt not canonicalisable: ${exc.message}`]];
    throw exc;
  }
  if (!VERDICTS.includes(r.verdict as "ALLOW" | "DENY"))
    return [false, ["verdict: outside the closed ALLOW/DENY enum"]];
  if (typeof envelope !== "object" || envelope === null || !("mandate_ref" in envelope))
    return [false, ["schema: envelope must carry a mandate_ref"]];
  if (r.mandate_ref !== envelope.mandate_ref)
    reasons.push("ref: receipt mandate_ref != envelope mandate_ref");
  try {
    if (r.policy_bound_ref !== policyBoundRef(envelope))
      reasons.push("ref: policy_bound_ref does not recompute from the envelope");
    const expectedGref = guardrailRef(
      r.agent_ref as string, envelope.mandate_ref as string,
      r.policy_bound_ref as string, r.verdict as string,
    );
    if (r.guardrail_ref !== expectedGref) reasons.push("ref: guardrail_ref does not recompute");
  } catch (exc) {
    if (exc instanceof L1Error || exc instanceof JcsError)
      reasons.push(`ref: cannot recompute decision refs: ${exc.message}`);
    else throw exc;
  }
  let entries: Entry[] = [];
  if (ledgerSnapshot !== null && ledgerSnapshot !== undefined) {
    entries = (ledgerSnapshot.entries as Entry[]) ?? [];
    const [ok, creasons] = verifyChain(entries);
    if (!ok) reasons.push(...creasons.map((x) => `ledger: ${x}`));
  }
  let now: Date;
  try {
    now = parse(r.issued_at as string);
  } catch {
    return [false, ["schema: malformed issued_at"]];
  }
  let ev;
  try {
    ev = evaluate(
      envelope, r.intent, r.countersign, entries, r.agent_ref as string, now,
      r.verdict === "ALLOW" && ledgerSnapshot !== null && ledgerSnapshot !== undefined,
    );
  } catch (exc) {
    return [false, [`recompute: hostile receipt material: ${(exc as Error).message}`]];
  }
  if (ev.verdict !== r.verdict)
    reasons.push(`verdict: recomputes as ${ev.verdict}, receipt claims ${r.verdict}`);
  if (JSON.stringify(ev.reasons) !== JSON.stringify(r.reasons))
    reasons.push(`reasons: refusal reasons do not recompute (recomputed: ${JSON.stringify(ev.reasons)})`);
  return [reasons.length === 0, reasons];
}

export function verifySettlement(
  envelope: Envelope,
  decisionReceipt: Record<string, unknown>,
  settlement: unknown,
  ledgerSnapshot?: Record<string, unknown> | null,
): [boolean, string[]] {
  const reasons: string[] = [];
  if (typeof settlement !== "object" || settlement === null || Array.isArray(settlement))
    return [false, ["schema: settlement receipt must be an object"]];
  const s = settlement as Record<string, unknown>;
  try {
    const { settlement_receipt_ref: _sr, ...body } = s;
    if (s.settlement_receipt_ref !== ref(body))
      reasons.push("ref: settlement_receipt_ref does not recompute");
  } catch (exc) {
    if (exc instanceof JcsError) return [false, [`ref: settlement not canonicalisable: ${exc.message}`]];
    throw exc;
  }
  if (s.decision_receipt_ref !== decisionReceipt.receipt_ref)
    reasons.push("ref: settlement bound to a different decision");
  for (const f of ["mandate_ref", "guardrail_ref"]) {
    if (s[f] !== decisionReceipt[f]) reasons.push(`ref: settlement ${f} mismatch`);
  }
  const i = (decisionReceipt.intent as Record<string, unknown>) ?? {};
  try {
    if (s.intent_ref !== ref(i)) reasons.push("ref: settlement intent_ref mismatch");
  } catch (exc) {
    if (exc instanceof JcsError) return [false, [`ref: intent not canonicalisable: ${exc.message}`]];
    throw exc;
  }
  for (const f of ["charge_id", "amount", "asset", "payee"]) {
    if (s[f] !== i[f]) reasons.push(`ref: settlement ${f} mismatch`);
  }
  if (!s.settlement_ref) reasons.push("settlement: empty settlement_ref");
  const [ok, dreasons] = verifyDecision(envelope, decisionReceipt, ledgerSnapshot);
  if (!ok) reasons.push(...dreasons.map((r) => `decision: ${r}`));
  return [reasons.length === 0, reasons];
}
