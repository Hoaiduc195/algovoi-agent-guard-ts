/**
 * Ed25519 human-anchor keys. Raw 32-byte keys, base64url (no padding).
 *
 * Byte-compatible with the Python reference (algovoi_agent_guard.keys): the
 * human holds the private key OUTSIDE the agent's reach; the agent only ever
 * sees public material. kid = sha256(raw_pub)[:16]. verify() never raises:
 * malformed material is a false, not an exception, so a hostile payload cannot
 * crash the guard into a fail-open state.
 *
 * Pure-JS Ed25519 via @noble/curves (no native dependency; runs in Node and the
 * browser). Raw-key model matches cryptography.hazmat Ed25519 exactly.
 */
import { ed25519 } from "@noble/curves/ed25519";
import { sha256 } from "@noble/hashes/sha256";
import { bytesToHex } from "@noble/hashes/utils";

export class KeyFormatError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "KeyFormatError";
  }
}

const B64ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

function b64e(raw: Uint8Array): string {
  let out = "";
  for (let i = 0; i < raw.length; i += 3) {
    const b0 = raw[i]!;
    const b1 = i + 1 < raw.length ? raw[i + 1]! : 0;
    const b2 = i + 2 < raw.length ? raw[i + 2]! : 0;
    out += B64ALPHABET[b0 >> 2];
    out += B64ALPHABET[((b0 & 0x03) << 4) | (b1 >> 4)];
    if (i + 1 < raw.length) out += B64ALPHABET[((b1 & 0x0f) << 2) | (b2 >> 6)];
    if (i + 2 < raw.length) out += B64ALPHABET[b2 & 0x3f];
  }
  return out; // no padding
}

function b64d(s: string): Uint8Array {
  if (typeof s !== "string") throw new KeyFormatError("expected base64url string");
  if (!/^[A-Za-z0-9_-]*$/.test(s)) throw new KeyFormatError("bad base64url alphabet");
  const clean = s.replace(/=+$/, "");
  const out: number[] = [];
  let buffer = 0;
  let bits = 0;
  for (const ch of clean) {
    const v = B64ALPHABET.indexOf(ch);
    if (v < 0) throw new KeyFormatError("bad base64url character");
    buffer = (buffer << 6) | v;
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      out.push((buffer >> bits) & 0xff);
    }
  }
  return Uint8Array.from(out);
}

/** Return { privateB64, publicB64 } for a fresh Ed25519 key. */
export function generateKeypair(): { privateB64: string; publicB64: string } {
  const rawPriv = ed25519.utils.randomPrivateKey();
  const rawPub = ed25519.getPublicKey(rawPriv);
  return { privateB64: b64e(rawPriv), publicB64: b64e(rawPub) };
}

export function pubFromPriv(privB64: string): string {
  const raw = b64d(privB64);
  if (raw.length !== 32) throw new KeyFormatError("private key must be 32 raw bytes");
  return b64e(ed25519.getPublicKey(raw));
}

export function kidFor(pubB64: string): string {
  return bytesToHex(sha256(b64d(pubB64))).slice(0, 16);
}

export function sign(privB64: string, data: Uint8Array): string {
  const raw = b64d(privB64);
  if (raw.length !== 32) throw new KeyFormatError("private key must be 32 raw bytes");
  return b64e(ed25519.sign(data, raw));
}

/** True iff sig is a valid Ed25519 signature by pub over data. Never raises. */
export function verify(pubB64: string, data: Uint8Array, sigB64: string): boolean {
  try {
    const rawPub = b64d(pubB64);
    const rawSig = b64d(sigB64);
    if (rawPub.length !== 32 || rawSig.length !== 64) return false;
    return ed25519.verify(rawSig, data, rawPub);
  } catch {
    return false;
  }
}
