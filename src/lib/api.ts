/**
 * Frontend API client for the PERMAFROST Vault backend.
 * All methods call /api/* endpoints on the same origin.
 */

import type { VaultConfig, NetworkName, StorageMode, ContractConfig } from './vault-types.js';

const BASE = '/api';

async function json<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(`${BASE}${path}`, {
    headers: { 'Content-Type': 'application/json' },
    ...init,
  });
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
}

export const getStatus = () => json<StatusResponse>('/status');

// ── Init ──

export const initInstance = (network: NetworkName, storageMode: StorageMode, password?: string) =>
  json<{ ok: true }>('/init', {
    method: 'POST',
    body: JSON.stringify({ network, storageMode, password }),
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

// ── Reset ──

export const resetInstance = () =>
  json<{ ok: true }>('/reset', {
    method: 'POST',
    body: JSON.stringify({ confirm: 'RESET' }),
  });
