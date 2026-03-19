/**
 * Frontend API client for the PERMAFROST Vault backend.
 * All methods call /api/* endpoints on the same origin.
 */

import type { VaultConfig, NetworkName, StorageMode, ContractConfig } from './vault-types.js';

const BASE = '/api';
const SESSION_TOKEN_KEY = 'permafrost-session-token';
const SESSION_ROLE_KEY = 'permafrost-session-role';

function getAdminToken(): string | null {
  try { return sessionStorage.getItem(SESSION_TOKEN_KEY); } catch { return null; }
}

export function setAdminToken(token: string): void {
  try { sessionStorage.setItem(SESSION_TOKEN_KEY, token); } catch { /* ignore */ }
}

export function clearAdminToken(): void {
  try { sessionStorage.removeItem(SESSION_TOKEN_KEY); } catch { /* ignore */ }
}

export function hasAdminToken(): boolean {
  return !!getAdminToken();
}

export function getSessionRole(): string | null {
  try { return sessionStorage.getItem(SESSION_ROLE_KEY); } catch { return null; }
}

export function setSessionRole(role: string): void {
  try { sessionStorage.setItem(SESSION_ROLE_KEY, role); } catch { /* ignore */ }
}

export function clearSession(): void {
  clearAdminToken();
  try { sessionStorage.removeItem(SESSION_ROLE_KEY); } catch { /* ignore */ }
}

async function json<T>(path: string, init?: RequestInit): Promise<T> {
  const token = getAdminToken();
  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
    ...(token ? { Authorization: `Bearer ${token}` } : {}),
  };
  const res = await fetch(`${BASE}${path}`, { ...init, headers });
  const data = await res.json();
  if (!res.ok) throw new Error(data.error || `HTTP ${res.status}`);
  return data as T;
}

// ── Status ──

export interface StatusResponse {
  state: 'fresh' | 'locked' | 'ready';
  setupState?: VaultConfig['setupState'];
  storageMode?: StorageMode;
  network?: NetworkName;
  walletConfigured?: boolean;
  authMode?: 'password' | 'wallet';
}

export const getStatus = () => json<StatusResponse>('/status');

// ── Init ──

export const initInstance = (
  network: NetworkName,
  storageMode: StorageMode,
  password?: string,
  adminPassword?: string,
  authMode?: 'password' | 'wallet',
  walletAddress?: string,
  walletLabel?: string,
) =>
  json<{ ok: true; token?: string; role?: string; address?: string }>('/init', {
    method: 'POST',
    body: JSON.stringify({ network, storageMode, password, adminPassword, authMode, walletAddress, walletLabel }),
  });

// ── Admin ──

export const adminUnlock = (password: string) =>
  json<{ ok: true; token: string }>('/admin/unlock', {
    method: 'POST',
    body: JSON.stringify({ password }),
  });

// ── Unlock ──

export const unlock = (password: string) =>
  json<{ ok: true; config: VaultConfig }>('/unlock', {
    method: 'POST',
    body: JSON.stringify({ password }),
  });

// ── Config ──

export const getConfig = () => json<VaultConfig>('/config');

export const updateContracts = (contracts: ContractConfig[]) =>
  json<{ ok: true }>('/config/contracts', {
    method: 'POST',
    body: JSON.stringify({ contracts }),
  });

export const exportConfig = () => json<{ config: string }>('/config/export', { method: 'POST' });

export const importConfig = (config: VaultConfig) =>
  json<{ ok: true; config: VaultConfig }>('/config/import', {
    method: 'POST',
    body: JSON.stringify({ config }),
  });

// ── Wallet ──

export const generateWallet = () =>
  json<{ ok: true; mnemonic: string; config: VaultConfig }>('/wallet/generate', { method: 'POST' });

export const skipWallet = (dontShowAgain: boolean) =>
  json<{ ok: true }>('/wallet/skip', {
    method: 'POST',
    body: JSON.stringify({ dontShowAgain }),
  });

export const getWalletBalance = () =>
  json<{ balance: string; configured: boolean }>('/wallet/balance');

// ── DKG ──

export const saveDKG = (data: {
  threshold: number;
  parties: number;
  level: number;
  combinedPubKey: string;
  shareData: string;
}) =>
  json<{ ok: true }>('/dkg/save', {
    method: 'POST',
    body: JSON.stringify(data),
  });

// ── Balances ──

export const getBalances = () =>
  json<{ balances: Array<{ address: string; name: string; symbol: string; balance: string; decimals: number }> }>('/balances');

// ── TX ──

export const encodeTx = (method: string, params: string[], paramTypes: Array<'address' | 'u256' | 'bytes'>) =>
  json<{ calldata: string; messageHash: string }>('/tx/encode', {
    method: 'POST',
    body: JSON.stringify({ method, params, paramTypes }),
  });

export const simulateTx = (contract: string, method: string, params: unknown[], abi?: unknown[]) =>
  json<{ success: boolean; revert?: string; estimatedGas?: string }>('/tx/simulate', {
    method: 'POST',
    body: JSON.stringify({ contract, method, params, abi }),
  });

export const getBroadcastStatus = (messageHash: string) =>
  json<{ broadcast: boolean; transactionId?: string; estimatedFees?: string; error?: string }>(`/tx/broadcast-status/${messageHash}`);

export const broadcastTx = (data: {
  contract: string;
  method: string;
  params: unknown[];
  paramTypes?: Array<'address' | 'u256' | 'bytes'>;
  abi?: unknown[];
  signature: string;
  messageHash: string;
}) =>
  json<{ success: boolean; transactionId?: string; estimatedFees?: string; error?: string }>('/tx/broadcast', {
    method: 'POST',
    body: JSON.stringify(data),
  });

// ── Hosting ──

export const getHosting = () =>
  json<{ hosting: import('./vault-types.js').HostingConfig | null }>('/hosting');

export const updateHosting = (domain: string, httpsEnabled: boolean) =>
  json<{ ok: true; warning?: string; config: import('./vault-types.js').VaultConfig }>('/hosting', {
    method: 'POST',
    body: JSON.stringify({ domain, httpsEnabled }),
  });

export const removeHosting = () =>
  json<{ ok: true }>('/hosting', { method: 'DELETE' });

// ── Wallet Auth ──

export const getChallenge = () =>
  json<{ challenge: string }>('/auth/challenge');

export const verifyAuth = (challenge: string, signature: string, publicKey: string, sessionCode?: string) =>
  json<{ authenticated: boolean; needsInvite?: boolean; token?: string; role?: string; address?: string; label?: string }>('/auth/verify', {
    method: 'POST',
    body: JSON.stringify({ challenge, signature, publicKey, ...(sessionCode ? { sessionCode } : {}) }),
  });

export const redeemInvite = (challenge: string, signature: string, publicKey: string, inviteCode: string, label?: string) =>
  json<{ authenticated: boolean; token?: string; role?: string; address?: string; label?: string }>('/auth/redeem', {
    method: 'POST',
    body: JSON.stringify({ challenge, signature, publicKey, inviteCode, label }),
  });

export const getAuthMe = () =>
  json<{ authenticated: boolean; role?: string; address?: string }>('/auth/me');

// ── Users (admin) ──

export const listUsers = () => json<{ users: Array<{ address: string; role: string; label: string }> }>('/users');
export const addUser = (address: string, role: string, label: string) =>
  json<{ ok: true }>('/users', { method: 'POST', body: JSON.stringify({ address, role, label }) });
export const removeUser = (address: string) =>
  json<{ ok: true }>(`/users/${encodeURIComponent(address)}`, { method: 'DELETE' });
export const updateUserRole = (address: string, role: string) =>
  json<{ ok: true }>(`/users/${encodeURIComponent(address)}`, { method: 'PATCH', body: JSON.stringify({ role }) });

// ── Invites (admin) ──

export const listInvites = () => json<{ invites: Array<{ code: string; role: string; usesLeft: number; expiresAt: number }> }>('/invites');
export const createInvite = (maxUses: number, expiresAt: number, role?: string) =>
  json<{ ok: true; invite: { code: string } }>('/invites', { method: 'POST', body: JSON.stringify({ maxUses, expiresAt, role }) });
export const deleteInvite = (code: string) =>
  json<{ ok: true }>(`/invites/${code}`, { method: 'DELETE' });

// ── Visibility (admin) ──

export const getVisibility = () => json<{ everybodyCanRead: boolean }>('/invites/settings/visibility');
export const setVisibility = (everybodyCanRead: boolean) =>
  json<{ ok: true }>('/invites/settings/visibility', { method: 'POST', body: JSON.stringify({ everybodyCanRead }) });

// ── Manifest ──

export const getManifest = () =>
  json<{ manifestConfig: unknown }>('/manifest');

export const saveManifest = (manifestConfig: unknown) =>
  json<{ ok: true }>('/manifest', {
    method: 'POST',
    body: JSON.stringify({ manifestConfig }),
  });

export const readContract = (contract: string, method: string, abi?: unknown[]) =>
  json<{ result: Record<string, unknown> }>('/tx/read', {
    method: 'POST',
    body: JSON.stringify({ contract, method, abi }),
  });

export const getBlockHeight = () =>
  json<{ height: number }>('/tx/block-height');

// ── Relay ──

export const getActiveSessions = () =>
  json<{ active: number }>('/relay/sessions');

// ── Reset ──

export const resetInstance = () =>
  json<{ ok: true }>('/reset', {
    method: 'POST',
    body: JSON.stringify({ confirm: 'RESET' }),
  });
