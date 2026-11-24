/**
 * Charge intents and the human countersignature.
 *
 * The countersign is DISPLAYED-TEXT COMPATIBLE with the I-HITL Countersign
 * prototype: the human approves the exact string
 *   Approve #{guardrail_ref}: pay {amount} {asset} to {payee} (expires {expiry})
 * The verifier RECOMPUTES the text from the intent and refuses any divergence,
 * then checks the Ed25519 signature over the JCS body embedding that text. The
 * countersign binds the PROSPECTIVE ALLOW guardrail_ref; missing/forged/stale
 * countersign -> DENY. The agent can initiate but never approve.
 */
import { canonicalise, ref } from "./jcs.js";
import { REF_RE } from "./l1.js";
import * as keys from "./keys.js";
import { iso, parse, displayUtc } from "./time.js";

export const INTENT_TYPE = "charge_intent";
export const INTENT_VERSION = "1";

export class IntentError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "IntentError";
  }
}

export interface Intent {
  type: string;
  version: string;
  charge_id: string;
  mandate_ref: string;
  payee: string;
  amount: number | bigint;
  asset: string;
  at: string;
  settlement_ref: string | null;
  scope: string | null;
  [k: string]: unknown;
}

function isPositiveInt(v: unknown): v is number | bigint {
  if (typeof v === "bigint") return v > 0n;
  return typeof v === "number" && Number.isInteger(v) && v > 0;
}

export function makeIntent(opts: {
  chargeId: string;
  mandateRef: string;
  payee: string;
  amount: number | bigint;
  asset?: string;
  at?: Date;
  settlementRef?: string | null;
  scope?: string | null;
}): Intent {
  const { chargeId, mandateRef, payee, amount } = opts;
  const asset = opts.asset ?? "USDC";
  const settlementRef = opts.settlementRef ?? null;
  const scope = opts.scope ?? null;
  if (typeof chargeId !== "string" || !chargeId || chargeId.length > 128)
    throw new IntentError("charge_id must be a non-empty string <= 128 chars");
  if (typeof mandateRef !== "string" || !REF_RE.test(mandateRef))
    throw new IntentError("mandate_ref must be a sha256: 64-hex reference");
  if (typeof payee !== "string" || !payee)
    throw new IntentError("payee must be a non-empty string");
  if (!isPositiveInt(amount))
    throw new IntentError("amount must be a positive integer (minor units)");
  if (typeof asset !== "string" || !asset)
    throw new IntentError("asset must be a non-empty string");
  if (settlementRef !== null && typeof settlementRef !== "string")
    throw new IntentError("settlement_ref must be a string or None");
  if (scope !== null && (typeof scope !== "string" || !scope))
    throw new IntentError("scope must be a non-empty string or None");
  const at = opts.at ?? new Date();
  return {
    type: INTENT_TYPE,
    version: INTENT_VERSION,
    charge_id: chargeId,
    mandate_ref: mandateRef,
    payee,
    amount,
    asset,
    at: iso(at),
    settlement_ref: settlementRef,
    scope,
  };
}

export function intentRef(i: unknown): string {
  return ref(i);
}

/** The exact string shown to the human and covered by the countersign. */
export function approvalText(guardrailRef: string, intent: Intent, expiresAt: string): string {
  const expiresStr = displayUtc(parse(expiresAt));
  return (
    `Approve #${guardrailRef}: pay ${intent.amount} ${intent.asset} ` +
    `to ${intent.payee} (expires ${expiresStr})`
  );
}

export function approvalBody(
  guardrailRef: string,
  intent: Intent,
  expiresAt: string,
  humanPub: string,
): Record<string, unknown> {
  return {
    type: "algovoi_countersign",
    version: "1",
    approval_text: approvalText(guardrailRef, intent, expiresAt),
    guardrail_ref: guardrailRef,
    intent_ref: intentRef(intent),
    expires_at: expiresAt,
    human_pub: humanPub,
    kid: keys.kidFor(humanPub),
  };
}

/** Human countersign of the prospective ALLOW decision for this intent. */
export function approve(
  guardrailRef: string,
  intent: Intent,
  humanPriv: string,
  expiresAt: string,
): Record<string, unknown> {
  if (typeof guardrailRef !== "string" || !REF_RE.test(guardrailRef))
    throw new IntentError("guardrail_ref must be a sha256: 64-hex reference");
  const pub = keys.pubFromPriv(humanPriv);
  const body = approvalBody(guardrailRef, intent, expiresAt, pub);
  body.sig = keys.sign(humanPriv, canonicalise(withoutSig(body)));
  return body;
}

function withoutSig(o: Record<string, unknown>): Record<string, unknown> {
  const { sig: _sig, ...rest } = o;
  return rest;
}

/** Offline check: [ok, reasons]. Never raises. */
export function verifyApproval(
  approval: unknown,
  guardrailRef: string,
  intent: Intent,
  humanPub: string,
  now?: Date,
): [boolean, string[]] {
  const reasons: string[] = [];
  if (typeof approval !== "object" || approval === null || Array.isArray(approval))
    return [false, ["schema: approval must be an object"]];
  const a = approval as Record<string, unknown>;
  const need = ["approval_text", "guardrail_ref", "intent_ref", "expires_at", "human_pub", "kid", "sig"];
  const missing = need.filter((f) => !(f in a));
  if (missing.length) return [false, [`schema: missing fields ${JSON.stringify(missing)}`]];
  let expectedText: string;
  try {
    expectedText = approvalText(guardrailRef, intent, a.expires_at as string);
  } catch (exc) {
    return [false, [`schema: cannot recompute approval text: ${(exc as Error).message}`]];
  }
  if (a.approval_text !== expectedText)
    reasons.push("text: displayed approval text does not match the intent (hidden fields)");
  if (a.guardrail_ref !== guardrailRef)
    reasons.push("ref: countersign bound to a different guardrail_ref");
  let expectedIntentRef: string;
  try {
    expectedIntentRef = intentRef(intent);
  } catch (exc) {
    return [false, [`schema: cannot recompute intent_ref: ${(exc as Error).message}`]];
  }
  if (a.intent_ref !== expectedIntentRef)
    reasons.push("ref: countersign bound to a different intent");
  if (a.human_pub !== humanPub)
    reasons.push("key: countersign not under the mandate's human key");
  try {
    if (a.kid !== keys.kidFor(humanPub))
      reasons.push("key: kid does not match the mandate's human key");
  } catch {
    return [false, ["key: malformed human_pub"]];
  }
  let sigOk = false;
  try {
    sigOk = keys.verify(a.human_pub as string, canonicalise(withoutSig(a)), a.sig as string);
  } catch (exc) {
    return [false, [`schema: approval not canonicalisable: ${(exc as Error).message}`]];
  }
  if (!sigOk) reasons.push("sig: countersign signature invalid");
  const nowD = now ?? new Date();
  try {
    if (nowD.getTime() >= parse(a.expires_at as string).getTime())
      reasons.push("expired: countersign past expires_at");
  } catch {
    reasons.push("schema: malformed expires_at");
  }
  return [reasons.length === 0, reasons];
}
