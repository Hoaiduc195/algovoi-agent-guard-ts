/**
 * The human-signed mandate envelope around the frozen L1 spend authority.
 *
 * The four frozen L1 fields (payer, cap, period, revocation_state) produce the
 * canonical mandate_ref exactly as the public conformance vectors define it.
 * The envelope ADDS payee/scope/per-charge ceiling, the human public key, a
 * validity window and an Ed25519 signature over the whole body; it never alters
 * the frozen ref. Raising the cap means a new mandate_ref AND a new human
 * signature; an agent without the human key can produce neither. Revocation is
 * a new envelope with revocation_state="revoked" (a distinct L1 ref), signed by
 * the same human key.
 */
import * as keys from "./keys.js";
import { canonicalise } from "./jcs.js";
import { L1Error, mandateRef } from "./l1.js";
import { iso, parse } from "./time.js";

export const ENVELOPE_TYPE = "algovoi_mandate_envelope";
export const ENVELOPE_VERSION = "1";
export const DECIMAL_RE = /^[1-9][0-9]*$/;
export const REQUIRED = [
  "type", "version", "payer", "cap", "period", "revocation_state",
  "payee", "scope", "max_per_charge", "mandate_ref", "human_pub", "kid",
  "issued_at", "expires_at", "sig",
] as const;

export class MandateError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "MandateError";
  }
}

export type Mandate = Record<string, unknown>;

/** Everything the human signature covers (the envelope minus the sig). */
export function mandateBody(m: Mandate): Record<string, unknown> {
  const { sig: _sig, ...rest } = m;
  return rest;
}

export function issueMandate(opts: {
  payer: string;
  cap: string;
  humanPriv: string;
  period?: string;
  payee?: string;
  scope?: string[] | null;
  maxPerCharge?: string | null;
  ttlSecs?: number;
  now?: Date;
}): Mandate {
  const { payer, cap, humanPriv } = opts;
  const period = opts.period ?? "monthly";
  const payee = opts.payee ?? "*";
  const maxPerCharge = opts.maxPerCharge ?? null;
  const ttlSecs = opts.ttlSecs ?? 31_536_000;
  if (typeof payer !== "string" || !payer)
    throw new MandateError("payer must be a non-empty string");
  if (typeof cap !== "string" || !DECIMAL_RE.test(cap))
    throw new MandateError("cap must be a positive decimal string (minor units)");
  if (typeof period !== "string" || !period)
    throw new MandateError("period must be a non-empty string");
  if (typeof payee !== "string" || !payee)
    throw new MandateError("payee must be a non-empty string ('*' = any)");
  const scope = opts.scope ? [...opts.scope] : [];
  if (scope.some((s) => typeof s !== "string" || !s))
    throw new MandateError("scope entries must be non-empty strings");
  if (maxPerCharge !== null && (typeof maxPerCharge !== "string" || !DECIMAL_RE.test(maxPerCharge)))
    throw new MandateError("maxPerCharge must be a positive decimal string or None");
  if (!Number.isInteger(ttlSecs) || ttlSecs < 60)
    throw new MandateError("ttlSecs must be an integer >= 60");
  const now = opts.now ?? new Date();
  const pub = keys.pubFromPriv(humanPriv);
  const body: Mandate = {
    type: ENVELOPE_TYPE,
    version: ENVELOPE_VERSION,
    payer,
    cap,
    period,
    revocation_state: "active",
    payee,
    scope,
    max_per_charge: maxPerCharge,
    mandate_ref: mandateRef(payer, cap, period, "active"),
    human_pub: pub,
    kid: keys.kidFor(pub),
    issued_at: iso(now),
    expires_at: iso(new Date(now.getTime() + ttlSecs * 1000)),
  };
  body.sig = keys.sign(humanPriv, canonicalise(mandateBody(body)));
  return body;
}

/** Re-sign the same authority with revocation_state='revoked' (new L1 ref). */
export function revoke(m: Mandate, humanPriv: string): Mandate {
  const [ok, reasons] = verifyMandate(m, parse(m.issued_at as string));
  if (!ok && !reasons.join(" ").includes("revoked"))
    throw new MandateError(`cannot revoke an invalid mandate: ${JSON.stringify(reasons)}`);
  const body = mandateBody(m);
  body.revocation_state = "revoked";
  body.mandate_ref = mandateRef(
    body.payer as string, body.cap as string, body.period as string, "revoked",
  );
  body.sig = keys.sign(humanPriv, canonicalise(mandateBody(body)));
  return body;
}

/** Offline check: [ok, reasons]. Never raises; hostile input is a refusal. */
export function verifyMandate(m: unknown, now?: Date): [boolean, string[]] {
  const reasons: string[] = [];
  if (typeof m !== "object" || m === null || Array.isArray(m))
    return [false, ["schema: mandate must be an object"]];
  const env = m as Mandate;
  const missing = REQUIRED.filter((f) => !(f in env));
  if (missing.length) return [false, [`schema: missing fields ${JSON.stringify(missing)}`]];
  if (env.type !== ENVELOPE_TYPE || env.version !== ENVELOPE_VERSION)
    reasons.push("schema: wrong type/version");
  let expectedRef: string;
  try {
    expectedRef = mandateRef(
      env.payer as string, env.cap as string, env.period as string, env.revocation_state as string,
    );
  } catch (exc) {
    if (exc instanceof L1Error) return [false, [`l1: ${exc.message}`]];
    throw exc;
  }
  if (env.mandate_ref !== expectedRef)
    reasons.push("l1: mandate_ref does not recompute from the frozen fields");
  if (typeof env.human_pub !== "string" || typeof env.sig !== "string")
    return [false, ["schema: human_pub/sig must be strings"]];
  try {
    if (env.kid !== keys.kidFor(env.human_pub))
      reasons.push("key: kid does not match human_pub");
  } catch {
    return [false, ["key: malformed human_pub"]];
  }
  if (!keys.verify(env.human_pub, canonicalise(mandateBody(env)), env.sig))
    reasons.push("sig: envelope signature invalid under human_pub");
  if (env.revocation_state !== "active")
    reasons.push("revoked: mandate revocation_state is not active");
  const nowD = now ?? new Date();
  try {
    if (nowD.getTime() >= parse(env.expires_at as string).getTime())
      reasons.push("expired: mandate past expires_at");
    if (parse(env.issued_at as string).getTime() > nowD.getTime())
      reasons.push("not_yet_valid: issued_at in the future");
  } catch {
    reasons.push("schema: malformed issued_at/expires_at");
  }
  return [reasons.length === 0, reasons];
}
