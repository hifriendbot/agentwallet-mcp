#!/usr/bin/env node
/**
 * Live smoke test for the TaskMarket MCP tools.
 *
 * Drives the built AgentWallet MCP server over stdio JSON-RPC exactly like a
 * real MCP client, then calls each read-only TaskMarket tool against the live
 * marketplace API and prints the results. The gated create tool is exercised
 * in refusal mode (confirm=false) so no money moves and no task is created.
 *
 * Run with: node scripts/taskmarket-live-check.mjs
 */
import { spawn } from 'node:child_process';

const SRV = new URL('../build/index.js', import.meta.url).pathname;

function callTools(calls, env = {}) {
  const child = spawn('node', [SRV], {
    env: { ...process.env, ...env },
    stdio: ['pipe', 'pipe', 'pipe'],
  });
  let buf = '';
  const pending = new Map();
  const lines = [];

  child.stdout.on('data', (d) => {
    buf += d.toString();
    let idx;
    while ((idx = buf.indexOf('\n')) !== -1) {
      const line = buf.slice(0, idx);
      buf = buf.slice(idx + 1);
      if (!line.trim()) continue;
      try {
        const msg = JSON.parse(line);
        if (msg.id !== undefined && pending.has(msg.id)) {
          pending.get(msg.id)(msg);
          pending.delete(msg.id);
        }
      } catch { lines.push(line); }
    }
  });

  let id = 0;
  const proms = calls.map(([name, arguments_]) => {
    const reqId = ++id;
    return new Promise((resolve, reject) => {
      pending.set(reqId, resolve);
      child.stdin.write(JSON.stringify({
        jsonrpc: '2.0', id: reqId, method: 'tools/call',
        params: { name, arguments: arguments_ },
      }) + '\n');
      setTimeout(() => {
        if (pending.has(reqId)) { pending.delete(reqId); reject(new Error(`timeout on ${name}`)); }
      }, 30000);
    });
  });

  return Promise.all(proms).finally(() => { child.kill(); });
}

function textOf(resp) {
  const content = resp?.result?.content || [];
  const text = content.find((c) => c.type === 'text')?.text || '{}';
  try { return JSON.parse(text); } catch { return { raw: text }; }
}

console.log('TaskMarket MCP live check\n=========================');
console.log('server:', SRV, '\n');

const stats = await callTools([['taskmarket_market_stats', {}]]);
console.log('1) taskmarket_market_stats');
console.log(JSON.stringify(textOf(stats[0]), null, 2), '\n');

const search = await callTools([['taskmarket_search_tasks', { status: 'open', limit: 3 }]]);
console.log('2) taskmarket_search_tasks (status=open, limit=3)');
const s = textOf(search[0]);
console.log(JSON.stringify({ count: s.count, has_more: s.has_more, tasks: s.tasks }, null, 2), '\n');

let taskId = s.tasks?.[0]?.id;
if (!taskId) {
  const all = await callTools([['taskmarket_search_tasks', { status: 'open', limit: 1 }]]);
  taskId = textOf(all[0]).tasks?.[0]?.id;
}
if (taskId) {
  const get = await callTools([['taskmarket_get_task', { task_id: taskId }]]);
  console.log('3) taskmarket_get_task', taskId);
  const g = textOf(get[0]);
  console.log(JSON.stringify({
    id: g.id, status: g.status, mode: g.mode,
    reward: g.reward, submission_count: g.submissionCount,
    pending_actions: g.pendingActions,
  }, null, 2), '\n');

  const subs = await callTools([['taskmarket_list_submissions', { task_id: taskId }]]);
  console.log('4) taskmarket_list_submissions', taskId);
  const list = textOf(subs[0]);
  console.log(JSON.stringify(Array.isArray(list) ? { submissions: list.length } : list, null, 2), '\n');
}

console.log('5) taskmarket_create_task — refusal gate (confirm=false, no money moved)');
const create = await callTools([['taskmarket_create_task', {
  description: 'never created — live smoke test',
  reward_usdc: '2.00',
  duration_hours: 48,
  tags: ['test'],
  confirm: false,
  wallet_id: 1,
}]]);
console.log(JSON.stringify(textOf(create[0]), null, 2), '\n');

console.log('6) taskmarket_create_task — cap refusal (confirm=true but reward > cap, no payer reached)');
const cap = await callTools([['taskmarket_create_task', {
  description: 'never created — live smoke test',
  reward_usdc: '50.00',
  duration_hours: 48,
  tags: ['test'],
  confirm: true,
  max_reward_usdc: '1',
  wallet_id: 1,
}]]);
console.log(JSON.stringify(textOf(cap[0]), null, 2), '\n');

console.log('Live check complete.');
