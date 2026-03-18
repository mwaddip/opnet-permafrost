# Project Manifest Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Enable any OPNet project to define its operations as a declarative `.otzi.json` manifest that Ötzi imports, validates, and renders as a fully functional operations interface with live state reads, conditional visibility, and theme overrides.

**Architecture:** A manifest is a JSON file stored in VaultConfig. The frontend parses it into typed structures, polls contract state via the existing backend RPC, evaluates conditions to show/hide operations, renders operation cards with auto-filled params, and applies theme CSS variables. The backend gets a new route for contract reads. The existing encode/simulate/broadcast pipeline is reused.

**Tech Stack:** TypeScript types for manifest schema, React components for rendering, backend RPC reads via `opnet` SDK, CSS custom properties for theming.

**Spec:** `/home/mwaddip/projects/od/docs/plans/2026-03-18-otzi-project-manifest.md`

---

## File Structure

| File | Status | Responsibility |
|------|--------|---------------|
| `src/lib/manifest-types.ts` | New | TypeScript types for manifest schema |
| `src/lib/manifest.ts` | New | Manifest parser, validator, condition evaluator, format helpers |
| `src/lib/manifest-state.ts` | New | State poller — reads contract values on a timer, exposes React hook |
| `src/components/ManifestView.tsx` | New | Main manifest UI — status panel + operation cards |
| `src/components/OperationCard.tsx` | New | Single operation card — param inputs, auto-fill, execute button |
| `src/components/ManifestImport.tsx` | New | Import/export UI for Settings — file picker, address config |
| `src/components/SigningPage.tsx` | Modify | Render ManifestView when manifest is loaded instead of MessageBuilder |
| `src/components/Settings.tsx` | Modify | Embed ManifestImport |
| `src/lib/vault-types.ts` | Modify | Add manifest field to VaultConfig |
| `src/lib/api.ts` | Modify | Add manifest save/read endpoints, contract read endpoint |
| `src/App.tsx` | Modify | Apply theme from manifest |
| `backend/src/lib/types.ts` | Modify | Add manifest to VaultConfig |
| `backend/src/routes/config.ts` | Modify | Add manifest save/get routes |
| `backend/src/routes/tx.ts` | Modify | Add contract read route |

---

## Chunk 1: Types, Parser, and Backend

### Task 1: Manifest type definitions

**Files:**
- Create: `src/lib/manifest-types.ts`

- [ ] **Step 1: Write the manifest type system**

```typescript
// ── Manifest schema types ──

export interface ProjectManifest {
  version: number;
  name: string;
  description?: string;
  icon?: string;
  theme?: ManifestTheme;
  contracts: Record<string, ManifestContract>;
  reads?: Record<string, ManifestRead>;
  status?: ManifestStatusEntry[];
  operations: ManifestOperation[];
}

export interface ManifestTheme {
  accent?: string;
  accentHover?: string;
  bg?: string;
  radius?: string;
}

export interface ManifestContract {
  label: string;
  abi: unknown[] | string; // string = shorthand like "OP_20"
}

export interface ManifestRead {
  contract: string;
  method: string;
  returns: 'uint8' | 'uint256' | 'address' | 'bool' | 'string';
  format?: 'raw' | 'token8' | 'btc8' | 'percent8' | 'price8' | 'address';
}

export interface ManifestStatusEntry {
  label: string;
  read: string;
  map?: Record<string, string>;
}

export interface ManifestOperation {
  id: string;
  label: string;
  description?: string;
  contract: string; // contract key or "$dynamic"
  method: string;
  condition?: ManifestCondition;
  ownerOnly?: boolean;
  confirm?: string;
  params: ManifestParam[];
}

export interface ManifestParam {
  name: string;
  type: 'uint256' | 'address' | 'bool' | 'bytes';
  label?: string;
  scale?: number;
  placeholder?: string;
  source?: string; // "contract:<key>", "setting:<key>", "read:<key>"
}

// ── Conditions ──

export type ManifestCondition =
  | { read: string; eq: number | string | boolean }
  | { read: string; neq: number | string | boolean }
  | { read: string; gt: number }
  | { read: string; lt: number }
  | { blockWindow: { read: string; minBlocks?: number; maxBlocks?: number } }
  | { and: ManifestCondition[] }
  | { or: ManifestCondition[] }
  | { not: ManifestCondition };

// ── Address mapping (stored in VaultConfig) ──

export interface ManifestConfig {
  manifest: ProjectManifest;
  addresses: Record<string, string>; // contract key → on-chain address
  settings?: Record<string, string>; // custom settings (e.g., "router" → address)
}
```

- [ ] **Step 2: Verify**

Run: `npx tsc -b`

- [ ] **Step 3: Commit**

```bash
git add src/lib/manifest-types.ts
git commit -m "feat: manifest type definitions"
```

---

### Task 2: Manifest parser, validator, condition evaluator, and format helpers

**Files:**
- Create: `src/lib/manifest.ts`

- [ ] **Step 1: Write parser/validator/evaluator**

```typescript
import type {
  ProjectManifest, ManifestCondition, ManifestConfig,
  ManifestParam, ManifestRead,
} from './manifest-types';
import { OP20_METHODS } from './op20-methods';

// ── Validation ──

export function validateManifest(data: unknown): { valid: true; manifest: ProjectManifest } | { valid: false; error: string } {
  if (!data || typeof data !== 'object') return { valid: false, error: 'Manifest must be a JSON object' };
  const m = data as Record<string, unknown>;

  if (m.version !== 1) return { valid: false, error: `Unsupported manifest version: ${m.version}` };
  if (typeof m.name !== 'string' || !m.name) return { valid: false, error: 'Manifest requires a name' };
  if (!m.contracts || typeof m.contracts !== 'object') return { valid: false, error: 'Manifest requires contracts' };
  if (!Array.isArray(m.operations)) return { valid: false, error: 'Manifest requires operations array' };

  // Validate each operation has id, label, contract, method, params
  for (const op of m.operations as Record<string, unknown>[]) {
    if (!op.id || !op.label || !op.contract || !op.method) {
      return { valid: false, error: `Operation missing required fields: ${JSON.stringify(op)}` };
    }
    if (!Array.isArray(op.params)) {
      return { valid: false, error: `Operation "${op.id}" requires params array` };
    }
  }

  return { valid: true, manifest: data as ProjectManifest };
}

// ── ABI shorthand resolution ──

const OP20_ABI_SHORTHAND = OP20_METHODS.map(m => ({
  name: m.name,
  inputs: m.params.map(p => ({ name: p.name, type: p.type === 'u256' ? 'uint256' : p.type })),
  outputs: [],
  type: 'Function',
}));

export function resolveAbi(abi: unknown[] | string): unknown[] {
  if (typeof abi === 'string') {
    if (abi === 'OP_20') return OP20_ABI_SHORTHAND;
    if (abi === 'OP_20S') return OP20_ABI_SHORTHAND; // extend later
    if (abi === 'OP_721') return []; // extend later
    return [];
  }
  // Handle mixed array: strings (shorthands) + objects (custom)
  const result: unknown[] = [];
  for (const entry of abi) {
    if (typeof entry === 'string') {
      result.push(...resolveAbi(entry));
    } else {
      result.push(entry);
    }
  }
  return result;
}

// ── Condition evaluation ──

export function evaluateCondition(
  condition: ManifestCondition,
  reads: Record<string, unknown>,
  currentBlock?: number,
): boolean {
  if ('and' in condition) {
    return condition.and.every(c => evaluateCondition(c, reads, currentBlock));
  }
  if ('or' in condition) {
    return condition.or.some(c => evaluateCondition(c, reads, currentBlock));
  }
  if ('not' in condition) {
    return !evaluateCondition(condition.not, reads, currentBlock);
  }
  if ('blockWindow' in condition) {
    if (currentBlock === undefined) return false;
    const baseBlock = Number(reads[condition.blockWindow.read] ?? 0);
    if (!baseBlock) return false;
    if (condition.blockWindow.minBlocks !== undefined) {
      return currentBlock >= baseBlock + condition.blockWindow.minBlocks;
    }
    if (condition.blockWindow.maxBlocks !== undefined) {
      return currentBlock < baseBlock + condition.blockWindow.maxBlocks;
    }
    return true;
  }
  if ('eq' in condition) {
    return String(reads[condition.read]) === String(condition.eq);
  }
  if ('neq' in condition) {
    return String(reads[condition.read]) !== String(condition.neq);
  }
  if ('gt' in condition) {
    return Number(reads[condition.read] ?? 0) > condition.gt;
  }
  if ('lt' in condition) {
    return Number(reads[condition.read] ?? 0) < condition.lt;
  }
  return true;
}

// ── Format helpers ──

export function formatReadValue(value: unknown, format?: ManifestRead['format'], map?: Record<string, string>): string {
  const raw = String(value ?? '');
  if (map && map[raw]) return map[raw];

  const n = BigInt(raw || '0');
  switch (format) {
    case 'token8':
    case 'btc8':
    case 'price8': {
      const whole = n / 100_000_000n;
      const frac = n % 100_000_000n;
      const fracStr = frac.toString().padStart(8, '0').replace(/0+$/, '') || '0';
      const num = `${whole}.${fracStr}`;
      if (format === 'btc8') return `${num} BTC`;
      if (format === 'price8') return `$${num}`;
      return num;
    }
    case 'percent8': {
      const pct = Number(n) / 1_000_000;
      return `${pct.toFixed(2)}%`;
    }
    case 'address':
      return raw.length > 16 ? `${raw.slice(0, 10)}...${raw.slice(-6)}` : raw;
    default:
      return raw;
  }
}

// ── Param resolution ──

export function resolveParamValue(
  param: ManifestParam,
  config: ManifestConfig,
  reads: Record<string, unknown>,
): string | undefined {
  if (!param.source) return undefined;

  const [sourceType, sourceKey] = param.source.split(':');
  if (!sourceKey) return undefined;

  switch (sourceType) {
    case 'contract':
      return config.addresses[sourceKey];
    case 'setting':
      return config.settings?.[sourceKey];
    case 'read':
      return reads[sourceKey] !== undefined ? String(reads[sourceKey]) : undefined;
    default:
      return undefined;
  }
}

// ── Param encoding ──

export function encodeParamValue(value: string, param: ManifestParam): string {
  if (param.type === 'uint256' && param.scale) {
    const scaled = BigInt(Math.round(parseFloat(value) * param.scale));
    return scaled.toString();
  }
  return value;
}
```

- [ ] **Step 2: Verify**

Run: `npx tsc -b`

- [ ] **Step 3: Commit**

```bash
git add src/lib/manifest.ts
git commit -m "feat: manifest parser, condition evaluator, format helpers"
```

---

### Task 3: Backend — manifest storage + contract read route

**Files:**
- Modify: `backend/src/lib/types.ts`
- Modify: `backend/src/routes/config.ts`
- Modify: `backend/src/routes/tx.ts`
- Modify: `src/lib/api.ts`
- Modify: `src/lib/vault-types.ts`

- [ ] **Step 1: Add `manifestConfig` to VaultConfig**

In `backend/src/lib/types.ts`, add to the `VaultConfig` interface:
```typescript
  manifestConfig?: unknown; // ManifestConfig — stored opaque on backend
```

In `src/lib/vault-types.ts`, add to `VaultConfig`:
```typescript
  manifestConfig?: import('./manifest-types').ManifestConfig;
```

- [ ] **Step 2: Add manifest save/get routes to config.ts**

In `backend/src/routes/config.ts`, add two routes:

```typescript
  /** GET /api/manifest — get current manifest config */
  r.get('/manifest', (_req: Request, res: Response) => {
    try {
      const config = store.get();
      res.json({ manifestConfig: config.manifestConfig || null });
    } catch (e) {
      res.status(503).json({ error: (e as Error).message });
    }
  });

  /** POST /api/manifest — save manifest config */
  r.post('/manifest', requireAdmin, (req: Request, res: Response) => {
    const { manifestConfig } = req.body;
    try {
      store.update({ manifestConfig });
      res.json({ ok: true });
    } catch (e) {
      res.status(500).json({ error: (e as Error).message });
    }
  });
```

- [ ] **Step 3: Add contract read route to tx.ts**

In `backend/src/routes/tx.ts`, add a new route for reading contract state:

```typescript
  /** POST /api/tx/read — read a value from a contract */
  r.post('/read', async (req: Request, res: Response) => {
    const { contract: contractAddr, method, abi } = req.body as {
      contract: string;
      method: string;
      abi?: unknown;
    };
    try {
      const config = store.get();
      const provider = getProvider(config.network);
      const network = getNetwork(config.network);
      const contractAbi = abi ? (Array.isArray(abi) ? abi : [abi]) : OP_20_ABI;
      const contract = getContract(contractAddr, contractAbi as typeof OP_20_ABI, provider, network);
      type ContractFnMap = Record<string, (...args: unknown[]) => Promise<{ properties: Record<string, unknown> }>>;
      const c = contract as unknown as ContractFnMap;
      if (!c[method]) {
        res.status(400).json({ error: `Method "${method}" not found on contract` });
        return;
      }
      const result = await c[method]!();
      res.json({ result: result.properties });
    } catch (e) {
      res.status(500).json({ error: (e as Error).message });
    }
  });
```

- [ ] **Step 4: Add frontend API functions**

In `src/lib/api.ts`, add:

```typescript
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
```

- [ ] **Step 5: Verify both compile**

Run: `cd backend && npx tsc && cd .. && npx tsc -b`

- [ ] **Step 6: Commit**

```bash
git add backend/src/lib/types.ts backend/src/routes/config.ts backend/src/routes/tx.ts \
       src/lib/api.ts src/lib/vault-types.ts
git commit -m "feat: manifest storage, contract read route, API endpoints"
```

---

## Chunk 2: State Poller and UI Components

### Task 4: State poller with React hook

**Files:**
- Create: `src/lib/manifest-state.ts`

- [ ] **Step 1: Write the state polling hook**

```typescript
import { useState, useEffect, useRef, useCallback } from 'react';
import { readContract } from './api';
import type { ManifestConfig, ManifestRead } from './manifest-types';
import { resolveAbi } from './manifest';

const POLL_INTERVAL = 30_000; // 30 seconds

export function useManifestState(config: ManifestConfig | null) {
  const [reads, setReads] = useState<Record<string, unknown>>({});
  const [loading, setLoading] = useState(false);
  const pollRef = useRef<ReturnType<typeof setInterval> | null>(null);

  const fetchAll = useCallback(async () => {
    if (!config?.manifest.reads) return;

    const readDefs = config.manifest.reads;
    const entries = Object.entries(readDefs);
    if (entries.length === 0) return;

    setLoading(true);
    const results: Record<string, unknown> = {};

    await Promise.allSettled(
      entries.map(async ([key, def]: [string, ManifestRead]) => {
        const contractKey = def.contract;
        const address = config.addresses[contractKey];
        if (!address) return;

        const abi = config.manifest.contracts[contractKey]?.abi;
        const resolvedAbi = abi ? resolveAbi(abi) : undefined;

        try {
          const response = await readContract(address, def.method, resolvedAbi);
          // Extract the first property value from the result
          const props = response.result;
          const firstKey = Object.keys(props)[0];
          results[key] = firstKey ? props[firstKey] : undefined;
        } catch {
          // Silently skip failed reads
        }
      }),
    );

    setReads(prev => ({ ...prev, ...results }));
    setLoading(false);
  }, [config]);

  useEffect(() => {
    if (!config?.manifest.reads) return;

    fetchAll();
    pollRef.current = setInterval(fetchAll, POLL_INTERVAL);

    return () => {
      if (pollRef.current) clearInterval(pollRef.current);
    };
  }, [config, fetchAll]);

  return { reads, loading, refresh: fetchAll };
}
```

- [ ] **Step 2: Verify**

Run: `npx tsc -b`

- [ ] **Step 3: Commit**

```bash
git add src/lib/manifest-state.ts
git commit -m "feat: manifest state poller with React hook"
```

---

### Task 5: OperationCard component

**Files:**
- Create: `src/components/OperationCard.tsx`

- [ ] **Step 1: Write the operation card**

```typescript
import { useState } from 'react';
import { encodeTx } from '../lib/api';
import type { ManifestOperation, ManifestConfig } from '../lib/manifest-types';
import { resolveParamValue, encodeParamValue } from '../lib/manifest';

interface Props {
  operation: ManifestOperation;
  config: ManifestConfig;
  reads: Record<string, unknown>;
  onExecute: (contractAddress: string, method: string, params: string[], paramTypes: Array<'address' | 'u256' | 'bytes'>, messageHash: string, message: Uint8Array) => void;
  disabled?: boolean;
}

export function OperationCard({ operation, config, reads, onExecute, disabled }: Props) {
  const [values, setValues] = useState<Record<string, string>>(() => {
    const initial: Record<string, string> = {};
    for (const p of operation.params) {
      const resolved = resolveParamValue(p, config, reads);
      if (resolved) initial[p.name] = resolved;
    }
    return initial;
  });
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  const [confirming, setConfirming] = useState(false);

  const contractAddress = operation.contract === '$dynamic'
    ? values['$contract'] || ''
    : config.addresses[operation.contract] || '';

  const handleExecute = async () => {
    if (operation.confirm && !confirming) {
      setConfirming(true);
      return;
    }
    setConfirming(false);
    setError('');
    setLoading(true);

    try {
      const params: string[] = [];
      const paramTypes: Array<'address' | 'u256' | 'bytes'> = [];

      for (const p of operation.params) {
        if (p.name === '$contract') continue; // handled above
        const raw = values[p.name] || '';
        if (!raw && !p.source) { setError(`${p.label || p.name} is required`); setLoading(false); return; }
        const encoded = encodeParamValue(raw, p);
        params.push(encoded);
        paramTypes.push(p.type === 'uint256' ? 'u256' : p.type as 'address' | 'bytes');
      }

      const result = await encodeTx(operation.method, params, paramTypes);
      const msgBytes = new Uint8Array(result.calldata.match(/.{2}/g)!.map(b => parseInt(b, 16)));
      onExecute(contractAddress, operation.method, params, paramTypes, result.messageHash, msgBytes);
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="card" style={{ marginBottom: 12 }}>
      <h3 style={{ fontSize: 15, marginBottom: 4 }}>{operation.label}</h3>
      {operation.description && (
        <p style={{ fontSize: 12, color: 'var(--white-dim)', marginBottom: 12 }}>{operation.description}</p>
      )}

      {operation.params.map(p => {
        if (p.name === '$contract') {
          return (
            <div className="form-row" key={p.name}>
              <label>
                {p.label || 'Contract'}
                <select
                  value={values[p.name] || ''}
                  onChange={e => setValues(prev => ({ ...prev, [p.name]: e.target.value }))}
                >
                  <option value="">Select contract...</option>
                  {Object.entries(config.addresses).map(([key, addr]) => (
                    <option key={key} value={addr}>{config.manifest.contracts[key]?.label || key} ({addr.slice(0, 10)}...)</option>
                  ))}
                </select>
              </label>
            </div>
          );
        }

        const resolved = resolveParamValue(p, config, reads);
        const isAutoFilled = !!resolved;

        return (
          <div className="form-row" key={p.name}>
            <label>
              {p.label || p.name}
              {p.scale && <span style={{ fontSize: 11, color: 'var(--white-dim)', marginLeft: 6 }}>×{p.scale}</span>}
              <input
                value={values[p.name] || ''}
                onChange={e => setValues(prev => ({ ...prev, [p.name]: e.target.value }))}
                placeholder={p.placeholder}
                disabled={disabled || isAutoFilled}
                style={isAutoFilled ? { opacity: 0.6 } : {}}
              />
            </label>
          </div>
        );
      })}

      {error && <div className="warning" style={{ marginBottom: 8 }}>{error}</div>}

      {confirming && operation.confirm && (
        <div className="warning" style={{ marginBottom: 8 }}>{operation.confirm}</div>
      )}

      <div style={{ display: 'flex', gap: 8 }}>
        <button
          className="btn btn-primary"
          style={{ flex: 1 }}
          onClick={handleExecute}
          disabled={disabled || loading || !contractAddress}
        >
          {loading ? <span className="spinner" /> : confirming ? 'Confirm' : operation.label}
        </button>
        {confirming && (
          <button className="btn btn-secondary" onClick={() => setConfirming(false)}>Cancel</button>
        )}
      </div>
    </div>
  );
}
```

- [ ] **Step 2: Verify**

Run: `npx tsc -b`

- [ ] **Step 3: Commit**

```bash
git add src/components/OperationCard.tsx
git commit -m "feat: OperationCard — manifest operation renderer with param auto-fill"
```

---

### Task 6: ManifestView — status panel + operations list

**Files:**
- Create: `src/components/ManifestView.tsx`

- [ ] **Step 1: Write the manifest view**

```typescript
import type { ManifestConfig } from '../lib/manifest-types';
import { useManifestState } from '../lib/manifest-state';
import { evaluateCondition, formatReadValue } from '../lib/manifest';
import { OperationCard } from './OperationCard';

interface Props {
  config: ManifestConfig;
  onExecute: (contractAddress: string, method: string, params: string[], paramTypes: Array<'address' | 'u256' | 'bytes'>, messageHash: string, message: Uint8Array) => void;
  disabled?: boolean;
}

export function ManifestView({ config, onExecute, disabled }: Props) {
  const { reads, loading } = useManifestState(config);

  const manifest = config.manifest;
  const visibleOps = manifest.operations.filter(op => {
    if (!op.condition) return true;
    return evaluateCondition(op.condition, reads);
  });

  return (
    <div>
      {/* Project header */}
      <div style={{ marginBottom: 16 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 4 }}>
          {manifest.icon && <img src={manifest.icon} alt="" style={{ width: 24, height: 24, borderRadius: 4 }} />}
          <h2 style={{ margin: 0, fontSize: 16 }}>{manifest.name}</h2>
          {loading && <span className="spinner" style={{ width: 14, height: 14, borderWidth: 2 }} />}
        </div>
        {manifest.description && (
          <p style={{ fontSize: 12, color: 'var(--white-dim)', margin: 0 }}>{manifest.description}</p>
        )}
      </div>

      {/* Status panel */}
      {manifest.status && manifest.status.length > 0 && (
        <div className="card" style={{ marginBottom: 16 }}>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(140px, 1fr))', gap: 12 }}>
            {manifest.status.map(entry => {
              const readDef = manifest.reads?.[entry.read];
              const value = reads[entry.read];
              return (
                <div key={entry.read}>
                  <div style={{ fontSize: 11, color: 'var(--gray-light)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
                    {entry.label}
                  </div>
                  <div style={{ fontSize: 15, fontWeight: 600, fontFamily: 'monospace', marginTop: 2 }}>
                    {value !== undefined
                      ? formatReadValue(value, readDef?.format, entry.map)
                      : '—'}
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      )}

      {/* Operations */}
      {visibleOps.length === 0 && (
        <p style={{ fontSize: 13, color: 'var(--white-dim)' }}>No operations available in the current state.</p>
      )}
      {visibleOps.map(op => (
        <OperationCard
          key={op.id}
          operation={op}
          config={config}
          reads={reads}
          onExecute={onExecute}
          disabled={disabled}
        />
      ))}
    </div>
  );
}
```

- [ ] **Step 2: Verify**

Run: `npx tsc -b`

- [ ] **Step 3: Commit**

```bash
git add src/components/ManifestView.tsx
git commit -m "feat: ManifestView — status panel + conditional operation cards"
```

---

## Chunk 3: Import UI, Theme, Integration

### Task 7: ManifestImport — Settings UI for import + address config

**Files:**
- Create: `src/components/ManifestImport.tsx`

- [ ] **Step 1: Write the import/config component**

```typescript
import { useState, useEffect } from 'react';
import { getManifest, saveManifest } from '../lib/api';
import { validateManifest } from '../lib/manifest';
import type { ManifestConfig, ProjectManifest } from '../lib/manifest-types';

interface Props {
  disabled?: boolean;
}

export function ManifestImport({ disabled }: Props) {
  const [config, setConfig] = useState<ManifestConfig | null>(null);
  const [error, setError] = useState('');
  const [saving, setSaving] = useState(false);
  const [message, setMessage] = useState('');
  const [addresses, setAddresses] = useState<Record<string, string>>({});
  const [settings, setSettings] = useState<Record<string, string>>({});

  useEffect(() => {
    getManifest().then(r => {
      if (r.manifestConfig) {
        const mc = r.manifestConfig as ManifestConfig;
        setConfig(mc);
        setAddresses(mc.addresses || {});
        setSettings(mc.settings || {});
      }
    }).catch(() => {});
  }, []);

  const handleImport = () => {
    const input = document.createElement('input');
    input.type = 'file';
    input.accept = '.json,.otzi.json';
    input.onchange = async (e) => {
      const file = (e.target as HTMLInputElement).files?.[0];
      if (!file) return;
      try {
        const text = await file.text();
        const parsed = JSON.parse(text);
        const result = validateManifest(parsed);
        if (!result.valid) { setError(result.error); return; }

        // Initialize addresses for all contract keys
        const newAddresses: Record<string, string> = {};
        for (const key of Object.keys(result.manifest.contracts)) {
          newAddresses[key] = addresses[key] || '';
        }

        // Detect setting sources that need configuration
        const newSettings: Record<string, string> = {};
        for (const op of result.manifest.operations) {
          for (const p of op.params) {
            if (p.source?.startsWith('setting:')) {
              const settingKey = p.source.split(':')[1]!;
              newSettings[settingKey] = settings[settingKey] || '';
            }
          }
        }

        const mc: ManifestConfig = { manifest: result.manifest, addresses: newAddresses, settings: newSettings };
        setConfig(mc);
        setAddresses(newAddresses);
        setSettings(newSettings);
        setError('');
        setMessage(`Loaded "${result.manifest.name}" — configure contract addresses below.`);
      } catch (e) {
        setError((e as Error).message);
      }
    };
    input.click();
  };

  const handleSave = async () => {
    if (!config) return;
    setSaving(true);
    setError('');
    try {
      const mc: ManifestConfig = { ...config, addresses, settings };
      await saveManifest(mc);
      setConfig(mc);
      setMessage('Manifest saved.');
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setSaving(false);
    }
  };

  const handleRemove = async () => {
    setSaving(true);
    try {
      await saveManifest(null);
      setConfig(null);
      setAddresses({});
      setSettings({});
      setMessage('Manifest removed.');
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setSaving(false);
    }
  };

  const hasAllAddresses = config ? Object.values(addresses).every(a => a.trim()) : false;

  return (
    <div className="card" style={disabled ? { opacity: 0.5, pointerEvents: 'none' } : {}}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 12 }}>
        <h2 style={{ marginBottom: 0 }}>Project Manifest</h2>
        <button className="btn btn-secondary" style={{ fontSize: 13, padding: '6px 14px' }} onClick={handleImport}>
          {config ? 'Replace' : 'Import .otzi.json'}
        </button>
      </div>

      {!config && (
        <p style={{ fontSize: 13, color: 'var(--white-dim)' }}>
          Import a project manifest to configure custom contract operations, status panels, and theming.
        </p>
      )}

      {config && (
        <>
          <div style={{ marginBottom: 12, padding: 10, background: 'var(--bg)', borderRadius: 'var(--radius)', border: '1px solid var(--border-dim)' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
              {config.manifest.icon && <img src={config.manifest.icon} alt="" style={{ width: 20, height: 20, borderRadius: 4 }} />}
              <strong style={{ fontSize: 14 }}>{config.manifest.name}</strong>
            </div>
            {config.manifest.description && (
              <div style={{ fontSize: 12, color: 'var(--white-dim)', marginTop: 4 }}>{config.manifest.description}</div>
            )}
            <div style={{ fontSize: 11, color: 'var(--gray-light)', marginTop: 4 }}>
              {Object.keys(config.manifest.contracts).length} contracts · {config.manifest.operations.length} operations
              {config.manifest.reads ? ` · ${Object.keys(config.manifest.reads).length} reads` : ''}
            </div>
          </div>

          {/* Contract addresses */}
          <h3 style={{ fontSize: 14, marginBottom: 8 }}>Contract Addresses</h3>
          {Object.entries(config.manifest.contracts).map(([key, contract]) => (
            <div className="form-row" key={key}>
              <label>
                {contract.label} <span style={{ fontSize: 11, color: 'var(--gray-light)' }}>({key})</span>
                <input
                  value={addresses[key] || ''}
                  onChange={e => setAddresses(prev => ({ ...prev, [key]: e.target.value }))}
                  placeholder="0x..."
                  style={{ fontFamily: 'monospace', fontSize: 12 }}
                />
              </label>
            </div>
          ))}

          {/* Custom settings */}
          {Object.keys(settings).length > 0 && (
            <>
              <h3 style={{ fontSize: 14, marginBottom: 8, marginTop: 16 }}>Settings</h3>
              {Object.keys(settings).map(key => (
                <div className="form-row" key={key}>
                  <label>
                    {key}
                    <input
                      value={settings[key] || ''}
                      onChange={e => setSettings(prev => ({ ...prev, [key]: e.target.value }))}
                      placeholder="0x..."
                      style={{ fontFamily: 'monospace', fontSize: 12 }}
                    />
                  </label>
                </div>
              ))}
            </>
          )}

          {error && <div className="warning" style={{ marginBottom: 8 }}>{error}</div>}
          {message && <div style={{ fontSize: 13, color: 'var(--accent)', marginBottom: 8 }}>{message}</div>}

          <div style={{ display: 'flex', gap: 8 }}>
            <button className="btn btn-primary" style={{ flex: 1 }} onClick={handleSave}
              disabled={saving || !hasAllAddresses}>
              {saving ? <span className="spinner" /> : 'Save'}
            </button>
            <button className="btn btn-secondary" style={{ color: 'var(--red)' }} onClick={handleRemove} disabled={saving}>
              Remove
            </button>
          </div>
        </>
      )}
    </div>
  );
}
```

- [ ] **Step 2: Verify**

Run: `npx tsc -b`

- [ ] **Step 3: Commit**

```bash
git add src/components/ManifestImport.tsx
git commit -m "feat: ManifestImport — import, address config, save/remove"
```

---

### Task 8: Theme applier + logo color matching

**Files:**
- Modify: `src/App.tsx`

- [ ] **Step 1: Add theme application from manifest**

Read `src/App.tsx`. In the `App` component, after loading config, check for `manifestConfig.manifest.theme` and apply CSS variable overrides to `document.documentElement.style`.

Add a `useEffect` that:
1. Reads `config.manifestConfig?.manifest?.theme`
2. Sets CSS variables: `--accent`, `--accent-hover`, `--bg`, `--radius`
3. Cleans up on unmount (resets to defaults)

```typescript
// Inside App component, after config is loaded:
useEffect(() => {
  // Apply manifest theme
  const applyTheme = async () => {
    try {
      const { getConfig } = await import('./lib/api');
      const cfg = await getConfig();
      const theme = (cfg.manifestConfig as import('./lib/manifest-types').ManifestConfig | undefined)?.manifest?.theme;
      if (!theme) return;
      const root = document.documentElement;
      if (theme.accent) root.style.setProperty('--accent', theme.accent);
      if (theme.accentHover) root.style.setProperty('--accent-hover', theme.accentHover);
      if (theme.radius) root.style.setProperty('--radius', theme.radius);
    } catch { /* no manifest */ }
  };
  if (view === 'signing' || view === 'settings') applyTheme();
  return () => {
    // Reset to CSS defaults on unmount
    const root = document.documentElement;
    root.style.removeProperty('--accent');
    root.style.removeProperty('--accent-hover');
    root.style.removeProperty('--radius');
  };
}, [view]);
```

The OtziLogo and OtziWordmark SVGs already use `fill="currentColor"` which inherits from the `--accent` color via CSS, so the logo automatically color-matches the theme.

- [ ] **Step 2: Verify**

Run: `npx tsc -b`

- [ ] **Step 3: Commit**

```bash
git add src/App.tsx
git commit -m "feat: apply manifest theme as CSS variable overrides"
```

---

### Task 9: Integrate ManifestView into SigningPage + ManifestImport into Settings

**Files:**
- Modify: `src/components/SigningPage.tsx`
- Modify: `src/components/Settings.tsx`

- [ ] **Step 1: SigningPage — render ManifestView when manifest is loaded**

Read `src/components/SigningPage.tsx`. In the `build` phase, check if `config.manifestConfig` exists and has addresses configured. If so, render `ManifestView` instead of (or above) `MessageBuilder`.

Import:
```typescript
import { ManifestView } from './ManifestView';
import type { ManifestConfig } from '../lib/manifest-types';
```

In the build phase rendering (where `MessageBuilder` is rendered), add before it:
```typescript
{config.manifestConfig && (
  <ManifestView
    config={config.manifestConfig as ManifestConfig}
    onExecute={(contractAddr, method, params, paramTypes, messageHash, message) => {
      setMessageMeta({
        contractAddress: contractAddr,
        method,
        params: Object.fromEntries(params.map((v, i) => [paramTypes[i], v])),
        paramTypes,
        messageHash,
      });
      setMessage(message);
      setPhase('sign');
    }}
  />
)}
```

If manifest is loaded, hide or collapse the raw MessageBuilder (show it in a collapsed "Advanced" section).

- [ ] **Step 2: Settings — embed ManifestImport**

Read `src/components/Settings.tsx`. Import and render `ManifestImport` before the Contracts card:
```typescript
import { ManifestImport } from './ManifestImport';
```

Add between the token balances section and the Hosting card:
```typescript
<ManifestImport disabled={isLocked} />
```

- [ ] **Step 3: Verify**

Run: `npx tsc -b`

- [ ] **Step 4: Commit**

```bash
git add src/components/SigningPage.tsx src/components/Settings.tsx
git commit -m "feat: integrate ManifestView in SigningPage, ManifestImport in Settings"
```

---

### Task 10: Build, verify, Docker test

- [ ] **Step 1: Full build**

Run: `cd backend && npx tsc && cd .. && npx tsc -b && npm run build`

- [ ] **Step 2: Docker build**

Run: `docker build -t permafrost-vault .`

- [ ] **Step 3: Final commit and push**

```bash
git add -A
git commit -m "feat: project manifest system

Declarative .otzi.json manifests define contract operations, live
state reads with conditional visibility, param auto-fill, status
panels, and theme overrides. Projects write JSON, not code."
git push
```
