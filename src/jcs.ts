/**
 * RFC 8785 (JCS) canonicalisation for a float-free schema.
 *
 * Byte-compatible with the Python reference (algovoi_agent_guard.jcs) and the
 * estate's frozen L1 spend-authority refs: SHA-256 over RFC 8785 JCS.
 *
 * Schema restriction: strings, integers (safe Number or BigInt), booleans,
 * null, arrays and objects with string keys. Floats are rejected: money is
 * integer minor units or a decimal string, never a binary float, so a
 * signature can never depend on float noise.
 *
 * Key ordering is by UTF-16 code units (RFC 8785 3.2.3), which JavaScript's
 * native string comparison already implements. String escaping is the JSON
 * mandatory set (RFC 8785 3.2.2.2): quote, reverse solidus and U+0000-U+001F,
 * with the short forms \b \f \n \r \t and \u00xx for the rest. Lone surrogates
 * are rejected (not valid UTF-8, not canonicalisable).
 */
import { sha256 } from "@noble/hashes/sha256";
import { bytesToHex } from "@noble/hashes/utils";

export class JcsError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "JcsError";
  }
}

const HEX = "0123456789abcdef";

/** True if the string contains an unpaired UTF-16 surrogate. */
function hasLoneSurrogate(s: string): boolean {
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if (c >= 0xd800 && c <= 0xdbff) {
      const n = s.charCodeAt(i + 1);
      if (!(n >= 0xdc00 && n <= 0xdfff)) return true;
      i++; // paired; skip the low surrogate
    } else if (c >= 0xdc00 && c <= 0xdfff) {
      return true; // low surrogate without a preceding high
    }
  }
  return false;
}

/** JSON mandatory escaping, literal UTF-8 otherwise (Python json.dumps parity). */
function escapeString(s: string): string {
  if (hasLoneSurrogate(s)) {
    throw new JcsError("string is not valid UTF-8 (lone surrogate)");
  }
  let out = '"';
  for (const ch of s) {
    const cp = ch.codePointAt(0)!;
    if (ch === '"') out += '\\"';
    else if (ch === "\\") out += "\\\\";
    else if (cp === 0x08) out += "\\b";
    else if (cp === 0x09) out += "\\t";
    else if (cp === 0x0a) out += "\\n";
    else if (cp === 0x0c) out += "\\f";
    else if (cp === 0x0d) out += "\\r";
    else if (cp < 0x20) out += "\\u00" + HEX[(cp >> 4) & 0xf] + HEX[cp & 0xf];
    else out += ch;
  }
  return out + '"';
}

function serialise(obj: unknown): string {
  if (obj === null) return "null";
  const t = typeof obj;
  if (t === "boolean") return obj ? "true" : "false";
  if (t === "bigint") return (obj as bigint).toString();
  if (t === "number") {
    const n = obj as number;
    if (!Number.isFinite(n) || !Number.isInteger(n)) {
      throw new JcsError("floats are outside the float-free schema");
    }
    if (!Number.isSafeInteger(n)) {
      throw new JcsError("integer outside the safe-integer range; use BigInt");
    }
    return String(n);
  }
  if (t === "string") return escapeString(obj as string);
  if (Array.isArray(obj)) {
    return "[" + obj.map((v) => serialise(v)).join(",") + "]";
  }
  if (t === "object") {
    const rec = obj as Record<string, unknown>;
    const keys = Object.keys(rec);
    for (const k of keys) {
      if (typeof k !== "string") throw new JcsError("object keys must be strings");
    }
    // RFC 8785 3.2.3: UTF-16 code-unit order (JS native string comparison).
    keys.sort();
    return (
      "{" +
      keys.map((k) => escapeString(k) + ":" + serialise(rec[k])).join(",") +
      "}"
    );
  }
  throw new JcsError(`unsupported type: ${t}`);
}

const ENCODER = new TextEncoder();

/** Return the RFC 8785 canonical UTF-8 bytes of a float-free JSON value. */
export function canonicalise(obj: unknown): Uint8Array {
  return ENCODER.encode(serialise(obj));
}

export function sha256Hex(data: Uint8Array): string {
  return bytesToHex(sha256(data));
}

/** The estate's content-address form: sha256: + hex(SHA-256(JCS(obj))). */
export function ref(obj: unknown): string {
  return "sha256:" + sha256Hex(canonicalise(obj));
}
