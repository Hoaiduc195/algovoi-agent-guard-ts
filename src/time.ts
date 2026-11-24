/** UTC time helpers matching the Python reference's strftime formats. */

function pad(n: number, w = 2): string {
  return String(n).padStart(w, "0");
}

/** "%Y-%m-%dT%H:%M:%SZ" in UTC. */
export function iso(dt: Date): string {
  return (
    `${dt.getUTCFullYear()}-${pad(dt.getUTCMonth() + 1)}-${pad(dt.getUTCDate())}` +
    `T${pad(dt.getUTCHours())}:${pad(dt.getUTCMinutes())}:${pad(dt.getUTCSeconds())}Z`
  );
}

/** "%Y-%m-%d %H:%M UTC" (the displayed countersign expiry). */
export function displayUtc(dt: Date): string {
  return (
    `${dt.getUTCFullYear()}-${pad(dt.getUTCMonth() + 1)}-${pad(dt.getUTCDate())}` +
    ` ${pad(dt.getUTCHours())}:${pad(dt.getUTCMinutes())} UTC`
  );
}

/** Parse an ISO timestamp; a naive (zone-less) value is treated as UTC. */
export function parse(s: string): Date {
  if (typeof s !== "string") throw new TypeError("timestamp must be a string");
  let t = s.replace("Z", "+00:00");
  // If there is no timezone offset, assume UTC (Python fromisoformat parity).
  if (!/[+-]\d{2}:?\d{2}$/.test(t) && !/\+\d{2}:\d{2}$/.test(t)) {
    t = t + "+00:00";
  }
  const d = new Date(t);
  if (Number.isNaN(d.getTime())) throw new ValueError(`malformed timestamp: ${s}`);
  return d;
}

export class ValueError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ValueError";
  }
}

/** ISO-8601 week-numbering year and week (Python date.isocalendar parity). */
export function isoWeek(d: Date): { year: number; week: number } {
  const date = new Date(Date.UTC(d.getUTCFullYear(), d.getUTCMonth(), d.getUTCDate()));
  const dayNum = date.getUTCDay() || 7; // Mon=1 .. Sun=7
  date.setUTCDate(date.getUTCDate() + 4 - dayNum); // nearest Thursday
  const yearStart = new Date(Date.UTC(date.getUTCFullYear(), 0, 1));
  const week = Math.ceil(((date.getTime() - yearStart.getTime()) / 86400000 + 1) / 7);
  return { year: date.getUTCFullYear(), week };
}

/** Budget period bucket for a timestamp (matches ledger.period_key). */
export function periodKey(period: string, ts: string): string {
  const dt = parse(ts);
  if (period === "monthly") return `${dt.getUTCFullYear()}-${pad(dt.getUTCMonth() + 1)}`;
  if (period === "daily")
    return `${dt.getUTCFullYear()}-${pad(dt.getUTCMonth() + 1)}-${pad(dt.getUTCDate())}`;
  if (period === "yearly") return `${dt.getUTCFullYear()}`;
  if (period === "weekly") {
    const w = isoWeek(dt);
    return `${w.year}-W${pad(w.week)}`;
  }
  return "all";
}
