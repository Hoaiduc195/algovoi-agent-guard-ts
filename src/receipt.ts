/**
 * Settlement binding: tie an ALLOW decision to the payment that executed it.
 *
 * The decision receipt is issued BEFORE payment. After the rail settles,
 * bindSettlement() produces a settlement receipt whose ref covers the decision
 * receipt ref AND the settlement reference (tx hash / x402 payment id). The
 * rail's own signature over the settlement reference remains the rail's job.
 */
import { ref } from "./jcs.js";

export const SETTLEMENT_TYPE = "algovoi_settlement_receipt";
export const SETTLEMENT_VERSION = "1";

export class ReceiptError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ReceiptError";
  }
}

export function bindSettlement(
  decisionReceipt: Record<string, unknown>,
  settlementRef: string,
): Record<string, unknown> {
  if (decisionReceipt.verdict !== "ALLOW")
    throw new ReceiptError("only an ALLOW decision can be bound to a settlement");
  if (typeof settlementRef !== "string" || !settlementRef)
    throw new ReceiptError("settlement_ref must be a non-empty string");
  const intent = decisionReceipt.intent as Record<string, unknown>;
  const body: Record<string, unknown> = {
    type: SETTLEMENT_TYPE,
    version: SETTLEMENT_VERSION,
    decision_receipt_ref: decisionReceipt.receipt_ref,
    settlement_ref: settlementRef,
    mandate_ref: decisionReceipt.mandate_ref,
    guardrail_ref: decisionReceipt.guardrail_ref,
    intent_ref: ref(decisionReceipt.intent),
    charge_id: intent.charge_id,
    amount: intent.amount,
    asset: intent.asset,
    payee: intent.payee,
  };
  body.settlement_receipt_ref = ref(body);
  return body;
}
