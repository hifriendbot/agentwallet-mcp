/**
 * TaskMarket MCP integration for AgentWallet.
 *
 * TaskMarket (https://taskmarket.dev) is an onchain agent work marketplace on
 * Base: requesters escrow USDC, workers submit deliverables, and the requester
 * accepts a winner. This module exposes the marketplace to an AI agent through
 * read-only discovery tools plus one gated write tool (task creation).
 *
 * Task creation is an x402-paid endpoint: POST /api/tasks returns HTTP 402
 * with a payment challenge, and the agent's AgentWallet pays it on-chain and
 * retries with proof. That is exactly the flow this server already performs
 * for pay_x402, so the two products compose instead of overlapping.
 *
 * SECURITY INVARIANT: creating a task escrows real USDC. The create path is
 * therefore never automatic. It requires (1) explicit confirmation from the
 * operator and (2) a hard spending cap, both validated before any money moves.
 * The x402 challenge is additionally pinned to TaskMarket's own escrow policy
 * so a tampered or third-party challenge can never redirect the payment.
 */

import { safeFetch, assertPublicUrl } from './ssrf-guard.js';

/** Default production API base. Override only for testing. */
export const TASKMARKET_API_URL = process.env.TASKMARKET_API_URL || 'https://api.taskmarket.dev';

/**
 * Pinned TaskMarket create-task payment policy.
 *
 * The create endpoint's 402 challenge is only a quote from an untrusted
 * server. We accept payment only when every field matches TaskMarket's own
 * escrow on Base. This prevents a malicious or replay-injected challenge from
 * steering funds elsewhere.
 */
export const TASKMARKET_PAYMENT_POLICY = {
  resource: `${TASKMARKET_API_URL}/api/tasks`,
  method: 'POST',
  network: 'eip155:8453', // Base
  asset: '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913', // USDC on Base
  payTo: '0x3C0820e2dabD5FEAe1fd03B78079DEe15c7F83D8', // TaskMarket escrow
  maxTimeoutSeconds: 300,
} as const;

export interface TaskMarketX402Accept {
  scheme?: string;
  network?: string;
  amount?: string;
  maxAmountRequired?: string;
  asset?: string;
  payTo?: string;
  maxTimeoutSeconds?: number;
  extra?: { name?: string };
}

export interface TaskMarketX402Challenge {
  x402Version?: number;
  resource?: { url?: string };
  accepts?: TaskMarketX402Accept[];
}

/** Convert a base-unit reward string (e.g. "2000000") to human USDC. */
export function baseUnitsToUsdc(raw: string | undefined | null): string {
  if (!raw || !/^\d+$/.test(raw)) return '0';
  const padded = raw.padStart(7, '0');
  const whole = padded.slice(0, padded.length - 6) || '0';
  const frac = padded.slice(padded.length - 6).replace(/0+$/, '');
  return frac ? `${whole}.${frac}` : whole;
}

/** Convert a human USDC amount (e.g. "2") to base units (e.g. "2000000"). */
export function usdcToBaseUnits(amount: string): string {
  if (!/^\d+(\.\d+)?$/.test(amount)) {
    throw new Error(`Invalid USDC amount "${amount}". Must be a positive number (e.g. "0.5" or "2").`);
  }
  const [whole, frac = ''] = amount.split('.');
  const fracPadded = frac.slice(0, 6).padEnd(6, '0');
  return BigInt(whole + fracPadded).toString();
}

/**
 * Validate a TaskMarket x402 challenge against the pinned payment policy.
 *
 * Throws when any field mismatches, so the caller can never pay a challenge
 * that TaskMarket's own escrow did not issue.
 */
export function assertTaskMarketChallenge(
  challenge: TaskMarketX402Challenge,
  expectedRewardBaseUnits: string,
): TaskMarketX402Accept {
  const accepts = challenge.accepts;
  if (!accepts || accepts.length === 0) {
    throw new Error('TaskMarket create returned 402 without any payment options.');
  }
  const accept = accepts[0];

  const resourceUrl = challenge.resource?.url;
  if (resourceUrl && resourceUrl !== TASKMARKET_PAYMENT_POLICY.resource) {
    throw new Error(
      `TaskMarket payment blocked: challenge resource "${resourceUrl}" does not match the pinned ` +
      `TaskMarket create endpoint "${TASKMARKET_PAYMENT_POLICY.resource}".`
    );
  }
  if (accept.scheme !== 'exact') {
    throw new Error(`TaskMarket payment blocked: unsupported scheme "${accept.scheme}".`);
  }
  if (String(accept.network || '').toLowerCase() !== TASKMARKET_PAYMENT_POLICY.network) {
    throw new Error(
      `TaskMarket payment blocked: network "${accept.network}" is not ${TASKMARKET_PAYMENT_POLICY.network} (Base).`
    );
  }
  if (String(accept.asset || '').toLowerCase() !== TASKMARKET_PAYMENT_POLICY.asset.toLowerCase()) {
    throw new Error(
      `TaskMarket payment blocked: asset "${accept.asset}" is not the pinned Base USDC contract.`
    );
  }
  if (String(accept.payTo || '').toLowerCase() !== TASKMARKET_PAYMENT_POLICY.payTo.toLowerCase()) {
    throw new Error(
      `TaskMarket payment blocked: payTo "${accept.payTo}" is not TaskMarket's escrow address.`
    );
  }
  if (typeof accept.maxTimeoutSeconds === 'number' && accept.maxTimeoutSeconds > TASKMARKET_PAYMENT_POLICY.maxTimeoutSeconds) {
    throw new Error(
      `TaskMarket payment blocked: maxTimeoutSeconds ${accept.maxTimeoutSeconds} exceeds the pinned ` +
      `${TASKMARKET_PAYMENT_POLICY.maxTimeoutSeconds}.`
    );
  }

  // The challenge amount is the escrow amount, which must equal the reward the
  // agent asked to fund. A mismatch means the server and client disagree about
  // cost, so we refuse rather than pay the quoted amount.
  const quote = accept.amount || accept.maxAmountRequired || '';
  if (quote !== expectedRewardBaseUnits) {
    throw new Error(
      `TaskMarket payment blocked: quoted escrow ${quote} base units does not equal the requested ` +
      `reward ${expectedRewardBaseUnits}. Refusing to pay an unexpected amount.`
    );
  }

  return accept;
}

/** Shape of the payment callback the server injects (see index.ts). */
export type TaskMarketPayer = (accept: TaskMarketX402Accept) => Promise<{ txHash: string }>;

export interface TaskMarketSearchParams {
  status?: string;
  mode?: string;
  limit?: number;
  sort?: string;
  min_reward?: string;
  max_reward?: string;
}

/** Read-only: browse open marketplace tasks. */
export async function searchTasks(params: TaskMarketSearchParams = {}): Promise<unknown> {
  const qs = new URLSearchParams();
  qs.set('status', params.status || 'open');
  if (params.mode) qs.set('mode', params.mode);
  qs.set('limit', String(params.limit || 20));
  if (params.sort) qs.set('sort', params.sort);
  if (params.min_reward) qs.set('minReward', params.min_reward);
  if (params.max_reward) qs.set('maxReward', params.max_reward);

  const url = `${TASKMARKET_API_URL}/api/tasks?${qs.toString()}`;
  await assertPublicUrl(url);
  const res = await safeFetch(url, { signal: AbortSignal.timeout(30_000) });
  const data = await res.json();
  if (!res.ok) {
    const error = (data as { error?: string }).error || `HTTP ${res.status}`;
    throw new Error(`TaskMarket search failed: ${error}`);
  }
  return data;
}

/** Read-only: fetch one task by id. */
export async function getTask(taskId: string): Promise<unknown> {
  if (!/^0x[a-fA-F0-9]{64}$/.test(taskId)) {
    throw new Error(`Invalid TaskMarket task id "${taskId}". Expected a 0x-prefixed 64-hex id.`);
  }
  const url = `${TASKMARKET_API_URL}/api/tasks/${taskId}`;
  await assertPublicUrl(url);
  const res = await safeFetch(url, { signal: AbortSignal.timeout(30_000) });
  const data = await res.json();
  if (!res.ok) {
    const error = (data as { error?: string }).error || `HTTP ${res.status}`;
    throw new Error(`TaskMarket get failed: ${error}`);
  }
  return data;
}

/** Read-only: list submissions for a task. */
export async function listSubmissions(taskId: string): Promise<unknown> {
  if (!/^0x[a-fA-F0-9]{64}$/.test(taskId)) {
    throw new Error(`Invalid TaskMarket task id "${taskId}". Expected a 0x-prefixed 64-hex id.`);
  }
  const url = `${TASKMARKET_API_URL}/api/tasks/${taskId}/submissions`;
  await assertPublicUrl(url);
  const res = await safeFetch(url, { signal: AbortSignal.timeout(30_000) });
  const data = await res.json();
  if (!res.ok) {
    const error = (data as { error?: string }).error || `HTTP ${res.status}`;
    throw new Error(`TaskMarket submissions failed: ${error}`);
  }
  return data;
}

/** Read-only: marketplace stats. */
export async function marketStats(): Promise<unknown> {
  const url = `${TASKMARKET_API_URL}/api/market/stats`;
  await assertPublicUrl(url);
  const res = await safeFetch(url, { signal: AbortSignal.timeout(30_000) });
  const data = await res.json();
  if (!res.ok) {
    const error = (data as { error?: string }).error || `HTTP ${res.status}`;
    throw new Error(`TaskMarket stats failed: ${error}`);
  }
  return data;
}

export interface TaskMarketCreateParams {
  description: string;
  reward_usdc: string;
  duration_hours: number;
  tags: string[];
  mode?: string;
  confirm: boolean;
  max_reward_usdc: string;
  payer: TaskMarketPayer;
}

export interface TaskMarketCreateResult {
  status: 'refused' | 'created';
  reason?: string;
  taskId?: string;
  txHash?: string;
  taskUrl?: string;
  reward_usdc?: string;
}

/**
 * Create and fund a TaskMarket task.
 *
 * Gated: requires `confirm: true` and a reward at or under `max_reward_usdc`.
 * Without confirmation, or over budget, it refuses without touching the
 * network. With confirmation it POSTs, pays the pinned x402 challenge through
 * the injected AgentWallet payer, retries with proof, and returns the task id.
 */
export async function createTask(params: TaskMarketCreateParams): Promise<TaskMarketCreateResult> {
  const { description, reward_usdc, duration_hours, tags, mode, confirm, max_reward_usdc, payer } = params;

  if (!confirm) {
    return {
      status: 'refused',
      reason:
        'Task creation escrows real USDC and was not confirmed. Re-run with confirm=true ' +
        'after reviewing the description, reward, deadline, and deliverable.',
    };
  }

  const rewardBase = usdcToBaseUnits(reward_usdc);
  const capBase = usdcToBaseUnits(max_reward_usdc);
  if (BigInt(rewardBase) > BigInt(capBase)) {
    return {
      status: 'refused',
      reason: `Reward ${reward_usdc} USDC exceeds the configured cap ${max_reward_usdc} USDC. No task was created.`,
    };
  }

  if (!description.trim() || description.length > 10000) {
    throw new Error('Task description must be between 1 and 10000 characters.');
  }
  if (!Number.isFinite(duration_hours) || duration_hours <= 0) {
    throw new Error('duration_hours must be a positive number.');
  }
  if (tags.length === 0 || tags.length > 10) {
    throw new Error('Provide between 1 and 10 tags.');
  }

  const body: Record<string, unknown> = {
    description,
    reward: rewardBase,
    duration: duration_hours,
    tags,
  };
  if (mode) body.mode = mode;

  const url = `${TASKMARKET_API_URL}/api/tasks`;
  await assertPublicUrl(url);

  const reqOptions: RequestInit = {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
    body: JSON.stringify(body),
    signal: AbortSignal.timeout(30_000),
  };

  const initialRes = await safeFetch(url, reqOptions);

  // No payment required — the task already exists.
  if (initialRes.status !== 402) {
    const text = await initialRes.text();
    let parsed: unknown;
    try { parsed = JSON.parse(text); } catch { parsed = text; }
    if (!initialRes.ok) {
      const error = (parsed as { error?: string })?.error || `HTTP ${initialRes.status}`;
      throw new Error(`TaskMarket create failed: ${error}`);
    }
    const taskId = (parsed as { taskId?: string })?.taskId;
    return {
      status: 'created',
      taskId,
      taskUrl: taskId ? `https://tasks.taskmarket.dev/tasks/${taskId}` : undefined,
      reward_usdc,
    };
  }

  // 402: parse and validate the challenge against the pinned policy.
  let challenge: TaskMarketX402Challenge;
  try {
    challenge = (await initialRes.json()) as TaskMarketX402Challenge;
  } catch {
    throw new Error('TaskMarket create returned 402 without a valid JSON challenge.');
  }
  const accept = assertTaskMarketChallenge(challenge, rewardBase);

  // The x402 amount is in base units and equals the escrowed reward (checked
  // above by assertTaskMarketChallenge).
  const { txHash } = await payer(accept);

  // Retry with the payment proof.
  const proof = {
    x402Version: challenge.x402Version || 1,
    scheme: 'exact',
    network: accept.network,
    payload: { txHash },
  };
  const paymentHeader = Buffer.from(JSON.stringify(proof)).toString('base64');
  const retryOptions: RequestInit = {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      Accept: 'application/json',
      'X-PAYMENT': paymentHeader,
    },
    body: JSON.stringify(body),
    signal: AbortSignal.timeout(30_000),
  };

  const retryRes = await safeFetch(url, retryOptions);
  const retryText = await retryRes.text();
  let retryParsed: unknown;
  try { retryParsed = JSON.parse(retryText); } catch { retryParsed = retryText; }
  if (!retryRes.ok) {
    const error = (retryParsed as { error?: string })?.error || `HTTP ${retryRes.status}`;
    throw new Error(`TaskMarket create failed after payment: ${error}`);
  }

  const taskId = (retryParsed as { taskId?: string })?.taskId;
  return {
    status: 'created',
    taskId,
    txHash,
    taskUrl: taskId ? `https://tasks.taskmarket.dev/tasks/${taskId}` : undefined,
    reward_usdc,
  };
}
