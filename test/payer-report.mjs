// Merge pay-bazaar result files into the PAYMENTS.md table. Usage: node test/payer-report.mjs <date> <results.json>...
import fs from 'node:fs';
const [date, ...files] = process.argv.slice(2);
const rows = new Map();
for (const f of files) for (const r of JSON.parse(fs.readFileSync(f, 'utf8'))) if (!rows.has(r.url) || r.tx) rows.set(r.url, r);
const settled = [...rows.values()].filter(r => r.tx && r.tx.startsWith('0x'));
const free = [...rows.values()].filter(r => r.payment_required === false);
const throttled = [...rows.values()].filter(r => !r.tx && /Rate limit exceeded/.test(String(r.error || '')));
const rejected = [...rows.values()].filter(r => !r.tx && r.payment_required !== false && !throttled.includes(r));
const host = u => new URL(u).host;
let md = `\n## x402 Payer Report, ${date}\n\nEvery endpoint in the x402 Bazaar discovery index priced at 0.01 USDC or less on Base, paid once each from a hosted AgentWallet with a 0.01 cap, x402 v2, exact scheme, EIP-3009 authorization. The payer wallet held 0 ETH throughout; facilitators paid the gas.\n\n**${settled.length} settled, ${free.length} answered without asking for payment, ${rejected.length} could not be paid** (rejected our request or asked again after payment; listed so operators can check their side)${throttled.length ? `, ${throttled.length} not attempted yet (the payer's own API rate limit, will be retried)` : ''}.\n\n| Endpoint | Amount | Settlement |\n| --- | --- | --- |\n`;
for (const r of settled.sort((a, b) => a.url.localeCompare(b.url))) md += `| \`${r.method} ${r.url}\` | ${r.amount} USDC | [${r.tx.slice(0, 10)}...](https://basescan.org/tx/${r.tx}) |\n`;
if (rejected.length) {
  md += `\n<details><summary>Not payable on ${date} (${rejected.length})</summary>\n\n| Endpoint | Result |\n| --- | --- |\n`;
  for (const r of rejected.sort((a, b) => a.url.localeCompare(b.url))) md += `| \`${r.url}\` | HTTP ${r.status ?? '-'}${r.error ? ': ' + String(r.error).replace(/\|/g, '/').slice(0, 120) : ''} |\n`;
  md += `\n</details>\n`;
}
if (free.length) md += `\nAnswered without a 402 (no payment needed): ${free.map(r => host(r.url)).join(', ')}.\n`;
fs.appendFileSync('PAYMENTS.md', md);
console.log(`settled ${settled.length}, free ${free.length}, rejected ${rejected.length}; hosts paid: ${new Set(settled.map(r => host(r.url))).size}`);
