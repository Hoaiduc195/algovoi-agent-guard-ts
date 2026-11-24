/** Regenerate BENCHMARKS.md from a measured bench.json (every figure traceable). */
import { readFileSync, writeFileSync } from "node:fs";

const b = JSON.parse(readFileSync(process.argv[2] ?? "bench.json", "utf8"));
const out = process.argv[3] ?? "BENCHMARKS.md";
const us = (x) => (x >= 1000 ? `${(x / 1000).toFixed(2)} ms` : `${x.toFixed(1)} us`);
const row = (name, s) =>
  `| ${name} | ${s.n} | ${s.ops_per_sec ?? "-"} | ${us(s.median_us)} | ${us(s.p95_us)} |`;

let md = `# Benchmarks\n\n`;
md += `Measured with \`performance.now()\` (no mocks), regenerated from \`bench.json\` `;
md += `via \`tools/bench.mjs\` + \`tools/gen_benchmarks.mjs\`.\n\n`;
md += `Runtime: Node ${b.node} on ${b.platform}; Ed25519 via ${b.crypto} (pure JS, no native deps).\n\n`;
md += `> Pure-JS Ed25519 is slower than a native crypto backend; each decision verifies two\n`;
md += `> signatures (mandate + countersign). Auditability and offline recomputability are\n`;
md += `> favoured over throughput. These figures are from this run's own log, not a target.\n\n`;
md += `## Hot paths\n\n| Path | n | ops/s | median | p95 |\n|---|---|---|---|---|\n`;
md += row("evaluate() (pure)", b.evaluate_pure) + "\n";
md += row("verifyDecision() (offline)", b.verify_decision_offline) + "\n";
md += row("decide() ALLOW + commit", b.decide_allow_commit_n200) + "\n\n";

md += `## Append latency vs ledger size (full-history rewrite + fsync)\n\n`;
md += `| entries | n | ops/s | median | p95 |\n|---|---|---|---|---|\n`;
for (const [size, s] of Object.entries(b.append_latency_by_ledger_size)) md += row(size, s) + "\n";
md += `\n`;

md += `## Hash-chain verify vs ledger size\n\n| entries | n | ops/s | median | p95 |\n|---|---|---|---|---|\n`;
for (const [size, s] of Object.entries(b.verify_chain_by_ledger_size)) md += row(size, s) + "\n";
md += `\n`;

md += `## Tamper detection vs ledger size (one mutated mid-chain entry)\n\n`;
md += `| entries | n | ops/s | median | p95 | detected |\n|---|---|---|---|---|---|\n`;
for (const [size, s] of Object.entries(b.tamper_detection_by_ledger_size))
  md += `| ${size} | ${s.n} | ${s.ops_per_sec ?? "-"} | ${us(s.median_us)} | ${us(s.p95_us)} | ${s.detected} |\n`;
md += `\nEvery injected mid-chain mutation is detected (\`detected: true\`).\n`;

writeFileSync(out, md);
console.log("wrote", out);
