/**
 * The guard: fail-closed admission over a human-signed mandate.
 *
 * Stateless recomputable admission: the guard holds NO signing key. Every
 * decision (ALLOW or DENY) is a content-addressed receipt any third party can
 * re-derive offline (see verify.ts). evaluate() is the PURE decision function;
 * Guard.decide() and verifyDecision() both call it, so a receipt recomputes by
 * construction. Check order: intent schema -> authority binding -> mandate
 * validity -> payee -> scope -> per-charge cap -> period cap -> replay -> human
 * countersign. Any failure is DENY with reasons; hostile input never raises and
 * never fails open. Only ALLOW appends to the ledger, after a valid countersign.
 */
import * as intentMod from "./intent.js";
import * as mandate from "./mandate.js";
import { JcsError, canonicalise, ref } from "./jcs.js";
import { REF_RE, guardrailRef } from "./l1.js";
import { Ledger, LedgerError, periodKey, type Entry } from "./ledger.js";
import { iso, parse } from "./time.js";

export const RECEIPT_TYPE = "algovoi_decision_receipt";
export const RECEIPT_VERSION = "1";

export class GuardError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "GuardError";
  }
}

export type Envelope = Record<string, unknown>;

/** Content-addressed deployed policy. Rotating any rule rotates the ref. */
export function policyBoundRef(envelope: Envelope): string {
  return ref({
    type: "algovoi_policy_bound",
    version: "1",
    payee: envelope.payee,
    scope: envelope.scope,
    max_per_charge: envelope.max_per_charge,
    cap: envelope.cap,
    period: envelope.period,
  });
}

function validateIntent(i: unknown): string[] {
  if (typeof i !== "object" || i === null || Array.isArray(i))
    return ["intent: must be an object"];
  const rec = i as Record<string, unknown>;
  try {
    intentMod.makeIntent({
      chargeId: rec.charge_id as string,
      mandateRef: rec.mandate_ref as string,
      payee: rec.payee as string,
      amount: rec.amount as number,
      asset: (rec.asset as string) ?? "USDC",
      settlementRef: rec.settlement_ref as string | null,
      scope: rec.scope as string | null,
    });
  } catch (exc) {
    if (exc instanceof intentMod.IntentError || exc instanceof TypeError)
      return [`intent: ${(exc as Error).message}`];
    throw exc;
  }
  if (!("at" in rec) || typeof rec.at !== "string")
    return ["intent: missing or non-string 'at'"];
  try {
    parse(rec.at);
  } catch (exc) {
    return [`intent: malformed 'at': ${(exc as Error).message}`];
  }
  try {
    canonicalise(rec);
  } catch (exc) {
    if (exc instanceof JcsError) return [`intent: outside float-free schema: ${exc.message}`];
    throw exc;
  }
  return [];
}

const LONE_SURROGATE = /[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/;

/** Map any value into the float-free, valid-UTF-8 JCS schema (refusal receipts). */
function safeJson(v: unknown): unknown {
  if (v === null || typeof v === "boolean") return v;
  if (typeof v === "bigint") return v;
  if (typeof v === "number") {
    if (Number.isInteger(v) && Number.isSafeInteger(v)) return v;
    return String(v);
  }
  if (typeof v === "string") {
    return LONE_SURROGATE.test(v) ? JSON.stringify(v) : v;
  }
  if (Array.isArray(v)) return v.map(safeJson);
  if (typeof v === "object") {
    const out: Record<string, unknown> = {};
    for (const [k, x] of Object.entries(v as Record<string, unknown>)) {
      const kk = LONE_SURROGATE.test(k) ? JSON.stringify(k) : k;
      out[kk] = safeJson(x);
    }
    return out;
  }
  return String(v).slice(0, 512);
}

function safeIntent(i: unknown): unknown {
  if (typeof i !== "object" || i === null || Array.isArray(i))
    return { malformed: true, repr: String(i).slice(0, 512) };
  return safeJson(i);
}

export interface Evaluation {
  verdict: "ALLOW" | "DENY";
  reasons: string[];
  policy_ref: string;
  allow_ref: string;
  deny_ref: string;
}

/** Pure decision. committed=true: the snapshot already contains this charge once. */
export function evaluate(
  envelope: Envelope,
  i: unknown,
  approval: unknown,
  entries: Entry[],
  agentRef: string,
  now: Date,
  committed = false,
): Evaluation {
  const policyRef = policyBoundRef(envelope);
  const mref = envelope.mandate_ref as string;
  const allowRef = guardrailRef(agentRef, mref, policyRef, "ALLOW");
  const denyRef = guardrailRef(agentRef, mref, policyRef, "DENY");
  const reasons = validateIntent(i);
  if (reasons.length === 0) {
    const intent = i as intentMod.Intent;
    if (intent.mandate_ref !== mref)
      reasons.push("mandate: intent bound to a different authority");
    const [ok, mreasons] = mandate.verifyMandate(envelope, now);
    if (!ok) reasons.push(...mreasons.map((r) => `mandate: ${r}`));
    if (envelope.payee !== "*" && intent.payee !== envelope.payee)
      reasons.push("policy: payee_not_allowed");
    const scope = envelope.scope as string[];
    if (Array.isArray(scope) && scope.length > 0 && !scope.includes(intent.scope as string))
      reasons.push("policy: scope_not_allowed");
    const amount = BigInt(intent.amount);
    if (envelope.max_per_charge !== null && amount > BigInt(envelope.max_per_charge as string))
      reasons.push("policy: per_charge_cap");
    const pk = periodKey(envelope.period as string, intent.at);
    let total = 0n;
    for (const e of entries) {
      if (e.period_key === pk && !(committed && e.charge_id === intent.charge_id))
        total += BigInt(e.amount);
    }
    if (total + amount > BigInt(envelope.cap as string))
      reasons.push("policy: period_cap");
    const mine = entries.filter((e) => e.charge_id === intent.charge_id);
    if (committed) {
      if (mine.length !== 1 || mine[0]!.guardrail_ref !== allowRef)
        reasons.push("ledger: ALLOW charge not committed exactly once under this ref");
    } else if (mine.length > 0) {
      reasons.push("policy: replay");
    }
    if (approval === null || approval === undefined) {
      reasons.push("countersign: required");
    } else {
      const [ok2, areasons] = intentMod.verifyApproval(
        approval, allowRef, intent, envelope.human_pub as string, now,
      );
      if (!ok2) reasons.push(...areasons.map((r) => `countersign: ${r}`));
    }
  }
  return {
    verdict: reasons.length ? "DENY" : "ALLOW",
    reasons,
    policy_ref: policyRef,
    allow_ref: allowRef,
    deny_ref: denyRef,
  };
}

export class Guard {
  envelope: Envelope;
  readonly humanPub: string;
  mandateRef_: string;
  policyRef: string;
  readonly agentRef: string;
  readonly ledger: Ledger;
  private _now: () => Date;

  constructor(envelope: Envelope, ledger: Ledger, agentRef: string, nowFn?: () => Date) {
    const [ok, reasons] = mandate.verifyMandate(envelope);
    if (!ok) throw new GuardError(`mandate invalid at construction: ${JSON.stringify(reasons)}`);
    if (typeof agentRef !== "string" || !REF_RE.test(agentRef))
      throw new GuardError("agent_ref must be a sha256: 64-hex reference");
    this.envelope = envelope;
    this.humanPub = envelope.human_pub as string; // PINNED: never read from input
    this.mandateRef_ = envelope.mandate_ref as string;
    this.policyRef = policyBoundRef(envelope);
    this.agentRef = agentRef;
    this.ledger = ledger;
    this._now = nowFn ?? (() => new Date());
  }

  setEnvelope(envelope: Envelope): void {
    if (
      envelope.kid !== this.envelope.kid ||
      envelope.human_pub !== this.humanPub ||
      envelope.payer !== this.envelope.payer
    )
      throw new GuardError("envelope swap refused: different human key or payer");
    const [ok, reasons] = mandate.verifyMandate(envelope);
    if (!ok && !reasons.some((r) => r.includes("revoked")))
      throw new GuardError(`envelope invalid: ${JSON.stringify(reasons)}`);
    this.envelope = envelope;
    this.mandateRef_ = envelope.mandate_ref as string;
    this.policyRef = policyBoundRef(envelope);
  }

  /** Return a decision receipt. Never raises; hostile input -> DENY. */
  decide(i: unknown, approval: unknown = null): Record<string, unknown> {
    const now = this._now();
    let ev = evaluate(this.envelope, i, approval, this.ledger.entries, this.agentRef, now, false);
    let intentOut = i;
    let approvalOut = approval;
    let ledgerFault: string | null = null;
    if (ev.verdict === "ALLOW") {
      const intent = i as intentMod.Intent;
      try {
        this.ledger.append({
          chargeId: intent.charge_id,
          amount: intent.amount,
          asset: intent.asset,
          payee: intent.payee,
          period: this.envelope.period as string,
          guardrailRef: ev.allow_ref,
          ts: intent.at,
        });
      } catch (exc) {
        // Fail-closed: ANY commit fault (LedgerError or unexpected) is a final
        // DENY; the pure policy is not re-run, so no exception escapes decide().
        ledgerFault = `ledger: ${(exc as Error).message}`;
      }
    }
    if (ledgerFault !== null) {
      intentOut = safeIntent(i);
      approvalOut = approval !== null && approval !== undefined ? safeJson(approval) : null;
      ev = {
        verdict: "DENY",
        reasons: [ledgerFault],
        policy_ref: ev.policy_ref,
        allow_ref: ev.allow_ref,
        deny_ref: ev.deny_ref,
      };
    } else if (ev.verdict === "DENY") {
      intentOut = safeIntent(i);
      approvalOut = approval !== null && approval !== undefined ? safeJson(approval) : null;
      const ev2 = evaluate(this.envelope, intentOut, approvalOut, this.ledger.entries, this.agentRef, now, false);
      if (ev2.verdict === "DENY") {
        ev = ev2;
      } else {
        ev = {
          verdict: "DENY",
          reasons: ["schema: refusal preserved after sanitisation"],
          policy_ref: ev.policy_ref,
          allow_ref: ev.allow_ref,
          deny_ref: ev.deny_ref,
        };
      }
    }
    return this._receipt(
      ev.verdict,
      ev.verdict === "ALLOW" ? ev.allow_ref : ev.deny_ref,
      intentOut,
      ev.reasons,
      approvalOut,
      now,
    );
  }

  private _receipt(
    verdict: string,
    gref: string,
    i: unknown,
    reasons: string[],
    approval: unknown,
    now: Date,
  ): Record<string, unknown> {
    const r: Record<string, unknown> = {
      type: RECEIPT_TYPE,
      version: RECEIPT_VERSION,
      verdict,
      guardrail_ref: gref,
      mandate_ref: this.mandateRef_,
      agent_ref: this.agentRef,
      policy_bound_ref: this.policyRef,
      intent: i,
      reasons,
      countersign: approval,
      ledger_head: this.ledger.head(),
      issued_at: iso(now),
    };
    r.receipt_ref = ref(r);
    return r;
  }
}
