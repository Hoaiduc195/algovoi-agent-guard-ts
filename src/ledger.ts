/**
 * Append-only, hash-chained spend ledger. Single writer, atomic appends.
 *
 * Each entry carries seq, the sha256 of the previous entry's JCS (genesis = 64
 * zeros), the charge facts and entry_ref = sha256(JCS(entry without entry_ref)).
 * Rewriting or deleting any entry breaks the chain; verifyChain() detects it
 * offline from public material alone. Duplicate charge_id is a replay, refused.
 */
import * as fs from "node:fs";
import { canonicalise, ref, sha256Hex } from "./jcs.js";
import { periodKey } from "./time.js";

export const GENESIS = "0".repeat(64);
export const LEDGER_TYPE = "algovoi_spend_ledger";
export const LEDGER_VERSION = "1";

export class LedgerError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "LedgerError";
  }
}

export interface Entry {
  seq: number;
  prev: string;
  charge_id: string;
  amount: number | bigint;
  asset: string;
  payee: string;
  period_key: string;
  guardrail_ref: string;
  ts: string;
  entry_ref: string;
  [k: string]: unknown;
}

export { periodKey };

export function entryRef(entry: Record<string, unknown>): string {
  const { entry_ref: _r, ...rest } = entry;
  return ref(rest);
}

/**
 * BigInt-safe JSONL serialisation. JSON.stringify throws on BigInt, so a valid
 * BigInt amount must be converted to an exact Number token within the safe
 * integer range (canonicalise renders both identically, so entry_ref recomputes
 * on reload). Beyond that range JS JSON cannot round-trip the integer exactly;
 * refuse fail-closed with a LedgerError rather than emit a lossy or throwing write.
 */
function stringifyEntry(e: Entry): string {
  return JSON.stringify(e, (_k, v) => {
    if (typeof v === "bigint") {
      if (v <= BigInt(Number.MAX_SAFE_INTEGER) && v >= -BigInt(Number.MAX_SAFE_INTEGER))
        return Number(v);
      throw new LedgerError("amount exceeds the safe integer range for JSON ledger storage");
    }
    return v;
  });
}

/** Offline: [ok, reasons]. Recomputes every entry_ref and prev link. */
export function verifyChain(entries: unknown): [boolean, string[]] {
  const reasons: string[] = [];
  if (!Array.isArray(entries)) return [false, ["schema: entries must be a list"]];
  let prev = GENESIS;
  const seen = new Set<unknown>();
  for (let n = 0; n < entries.length; n++) {
    const e = entries[n];
    if (typeof e !== "object" || e === null || Array.isArray(e))
      return [false, [`chain: entry ${n} not an object`]];
    const rec = e as Record<string, unknown>;
    if (rec.seq !== n) reasons.push(`chain: entry ${n} seq mismatch`);
    if (rec.prev !== prev) reasons.push(`chain: entry ${n} prev link broken`);
    if (!("entry_ref" in rec) || rec.entry_ref !== entryRef(rec))
      reasons.push(`chain: entry ${n} entry_ref does not recompute`);
    const cid = rec.charge_id;
    if (seen.has(cid)) reasons.push(`replay: charge_id ${JSON.stringify(cid)} appears twice`);
    seen.add(cid);
    prev = sha256Hex(canonicalise(rec));
  }
  return [reasons.length === 0, reasons];
}

export class Ledger {
  readonly path: string;
  private _entries: Entry[] = [];

  constructor(path: string) {
    this.path = String(path);
    if (fs.existsSync(this.path)) {
      let lines: string[];
      try {
        lines = fs.readFileSync(this.path, "utf8").split("\n").filter((l) => l.trim());
        this._entries = lines.map((l) => JSON.parse(l) as Entry);
      } catch (exc) {
        throw new LedgerError(`ledger unreadable: ${(exc as Error).message}`);
      }
      const [ok, reasons] = verifyChain(this._entries);
      if (!ok) throw new LedgerError(`ledger chain corrupt, refusing to operate: ${JSON.stringify(reasons)}`);
    }
  }

  get entries(): Entry[] {
    return [...this._entries];
  }

  head(): string {
    if (this._entries.length === 0) return GENESIS;
    return sha256Hex(canonicalise(this._entries[this._entries.length - 1]!));
  }

  hasCharge(chargeId: string): boolean {
    return this._entries.some((e) => e.charge_id === chargeId);
  }

  periodTotal(key: string): bigint {
    let total = 0n;
    for (const e of this._entries) if (e.period_key === key) total += BigInt(e.amount);
    return total;
  }

  append(opts: {
    chargeId: string;
    amount: number | bigint;
    asset: string;
    payee: string;
    period: string;
    guardrailRef: string;
    ts: string;
  }): Entry {
    const { chargeId, amount, asset, payee, period, guardrailRef, ts } = opts;
    if (this.hasCharge(chargeId))
      throw new LedgerError(`replay: charge_id ${JSON.stringify(chargeId)} already committed`);
    const amtOk =
      (typeof amount === "bigint" && amount > 0n) ||
      (typeof amount === "number" && Number.isInteger(amount) && amount > 0);
    if (!amtOk) throw new LedgerError("amount must be a positive integer");
    const entry: Entry = {
      seq: this._entries.length,
      prev: this.head(),
      charge_id: chargeId,
      amount,
      asset,
      payee,
      period_key: periodKey(period, ts),
      guardrail_ref: guardrailRef,
      ts,
      entry_ref: "",
    };
    entry.entry_ref = entryRef(entry);
    const [ok, reasons] = verifyChain([...this._entries, entry]);
    if (!ok) throw new LedgerError(`append would break chain: ${JSON.stringify(reasons)}`);
    const lock = this.path + ".lock";
    let fd: number | null = null;
    try {
      fd = fs.openSync(lock, "wx"); // O_CREAT | O_EXCL
      const tmp = this.path + ".tmp";
      const hist = [...this._entries, entry];
      const data = hist.map((e) => stringifyEntry(e)).join("\n") + "\n";
      const wfd = fs.openSync(tmp, "w");
      try {
        fs.writeSync(wfd, data);
        fs.fsyncSync(wfd);
      } finally {
        fs.closeSync(wfd);
      }
      fs.renameSync(tmp, this.path);
    } catch (exc) {
      if ((exc as NodeJS.ErrnoException).code === "EEXIST")
        throw new LedgerError("another writer holds the ledger lock");
      throw exc;
    } finally {
      if (fd !== null) {
        fs.closeSync(fd);
        try { fs.unlinkSync(lock); } catch { /* ignore */ }
      }
    }
    this._entries.push(entry);
    return entry;
  }

  snapshot(): Record<string, unknown> {
    return {
      type: LEDGER_TYPE,
      version: LEDGER_VERSION,
      entries: structuredClone(this._entries),
      head: this.head(),
    };
  }
}
