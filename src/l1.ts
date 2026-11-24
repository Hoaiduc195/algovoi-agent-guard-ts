/**
 * Frozen L1 spend-authority references (byte-compatible with the public vectors).
 *
 * Reproduces, exactly, the two published conformance sets:
 *  - payment_mandate_lite/v1:
 *      mandate_ref = "sha256:" + SHA-256(JCS({cap, payer, period, revocation_state}))
 *    All four fields are non-empty strings (cap is a string); an empty or
 *    missing field is rejected, not hashed.
 *  - spend_guardrail_lite/v1:
 *      guardrail_ref = "sha256:" + SHA-256(JCS({agent_ref, mandate_ref,
 *      policy_bound_ref, verdict})) with verdict in {ALLOW, DENY} and each ref
 *    a "sha256:" + 64 lowercase hex reference.
 *
 * This module adds no fields to the frozen format; the human-anchor signature
 * layer lives in mandate.ts as an envelope around these refs.
 */
import { ref } from "./jcs.js";

export const REF_RE = /^sha256:[0-9a-f]{64}$/;
export const VERDICTS = ["ALLOW", "DENY"] as const;
export type Verdict = (typeof VERDICTS)[number];
export const MANDATE_FIELDS = ["payer", "cap", "period", "revocation_state"] as const;

export class L1Error extends Error {
  constructor(message: string) {
    super(message);
    this.name = "L1Error";
  }
}

function nonemptyStr(name: string, value: unknown): string {
  if (typeof value !== "string" || value === "") {
    throw new L1Error(`${name} must be a non-empty string`);
  }
  return value;
}

function refForm(name: string, value: unknown): string {
  if (typeof value !== "string" || !REF_RE.test(value)) {
    throw new L1Error(`${name} must be a sha256: 64-hex reference`);
  }
  return value;
}

/** Content address of a spend authority. cap is a string (e.g. "1000"). */
export function mandateRef(
  payer: string,
  cap: string,
  period: string,
  revocationState: string,
): string {
  const payload = {
    payer: nonemptyStr("payer", payer),
    cap: nonemptyStr("cap", cap),
    period: nonemptyStr("period", period),
    revocation_state: nonemptyStr("revocation_state", revocationState),
  };
  return ref(payload);
}

/** Content address of a pre-payment ALLOW/DENY decision bound to its inputs. */
export function guardrailRef(
  agentRef: string,
  mandateRef_: string,
  policyBoundRef: string,
  verdict: string,
): string {
  if (!VERDICTS.includes(verdict as Verdict)) {
    throw new L1Error(`verdict must be one of ${VERDICTS.join(",")}`);
  }
  const payload = {
    agent_ref: refForm("agent_ref", agentRef),
    mandate_ref: refForm("mandate_ref", mandateRef_),
    policy_bound_ref: refForm("policy_bound_ref", policyBoundRef),
    verdict,
  };
  return ref(payload);
}
