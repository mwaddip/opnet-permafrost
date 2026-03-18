# OPWallet Authentication Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add optional OPWallet ML-DSA authentication with admin/user/everybody roles, invite codes, and role-based visibility — replacing admin password when enabled.

**Architecture:** Backend gets a `UserStore` (file-based user DB), ML-DSA challenge-response auth routes, and role-aware middleware. Frontend gets a wallet auth gate, role context, user/invite management in Settings, and an auth mode choice in the install wizard.

**Tech Stack:** `@btc-vision/post-quantum/ml-dsa.js` for server-side verification, `window.opnet` browser API for wallet signing, Express middleware for role enforcement, file-based JSON user store.

**Spec:** `docs/superpowers/specs/2026-03-18-wallet-auth-design.md`

---

## File Structure

| File | Status | Responsibility |
|------|--------|---------------|
| `backend/src/lib/users.ts` | New | UserStore class — CRUD users, invites, settings, file persistence |
| `backend/src/lib/auth.ts` | Rewrite | Token management, ML-DSA verification, challenge store, role-aware middleware factory |
| `backend/src/routes/auth.ts` | New | Auth routes: challenge, verify, redeem invite, /me |
| `backend/src/routes/users.ts` | New | Admin CRUD routes for users and invites |
| `backend/src/routes/config.ts` | Modify | Accept `authMode` in init, pass middleware |
| `backend/src/routes/wallet.ts` | Modify | Use `requireUser` on generate/skip |
| `backend/src/routes/tx.ts` | Modify | Use `requireUser` on encode/simulate/broadcast |
| `backend/src/routes/hosting.ts` | Modify | Use `requireRead` on GET, keep `requireAdmin` on POST/DELETE |
| `backend/src/routes/balances.ts` | Modify | Use `requireRead` |
| `backend/src/server.ts` | Modify | Init UserStore, register auth + user routes, pass middleware |
| `backend/src/lib/types.ts` | Modify | Add `authMode` to VaultConfig, update sanitize |
| `backend/package.json` | Modify | Add post-quantum vendor dep |
| `src/lib/api.ts` | Modify | Auth endpoints, role storage, rename token key |
| `src/lib/vault-types.ts` | Modify | Add `authMode` |
| `src/components/WalletAuth.tsx` | New | OPWallet connect, challenge-response, invite code flow |
| `src/components/UserManager.tsx` | New | User CRUD table + invite management (used in Settings) |
| `src/components/Settings.tsx` | Modify | Embed UserManager, add everybody-visibility toggle |
| `src/components/InstallWizard.tsx` | Modify | Auth mode step, wallet connect for first admin |
| `src/App.tsx` | Modify | Wallet auth gate, role context |

---

## Chunk 1: Backend — UserStore and Auth Infrastructure

### Task 1: Add post-quantum to backend deps

**Files:**
- Modify: `backend/package.json`

- [ ] **Step 1: Add the vendor post-quantum dependency**

In `backend/package.json`, add to `dependencies`:
```json
"@btc-vision/post-quantum": "file:../vendor/post-quantum"
```

- [ ] **Step 2: Install and verify**

Run: `cd backend && npm install`
Expected: Installs without error. `node -e "import('@btc-vision/post-quantum/ml-dsa.js').then(m => console.log(Object.keys(m)))"` should print the exports.

- [ ] **Step 3: Commit**

```bash
git add backend/package.json backend/package-lock.json
git commit -m "feat: add post-quantum vendor dep to backend"
```

---

### Task 2: Add `authMode` to VaultConfig

**Files:**
- Modify: `backend/src/lib/types.ts`

- [ ] **Step 1: Add `authMode` field to VaultConfig**

After `adminPasswordHash?` on line 45, add:
```typescript
  authMode?: 'password' | 'wallet';
```

- [ ] **Step 2: Include `authMode` in sanitizeConfig output**

The current `sanitizeConfig` strips `adminPasswordHash` and adds `hasAdminPassword`. It should also pass through `authMode`. The current implementation already uses spread (`...rest`) which includes `authMode`, so no change needed there — just verify it's passed through.

- [ ] **Step 3: Return `authMode` in status endpoint**

In `backend/src/routes/config.ts`, update the `GET /api/status` handler's ready response (line ~17) to include `authMode`:
```typescript
res.json({ state: 'ready', setupState, storageMode, network, walletConfigured, authMode: config.authMode || 'password' });
```

- [ ] **Step 4: Update `StatusResponse` in frontend**

In `src/lib/vault-types.ts`, add to VaultConfig:
```typescript
  authMode?: 'password' | 'wallet';
```

In `src/lib/api.ts`, add to `StatusResponse`:
```typescript
  authMode?: 'password' | 'wallet';
```

- [ ] **Step 5: Verify both compile**

Run: `cd backend && npx tsc && cd .. && npx tsc -b`

- [ ] **Step 6: Commit**

```bash
git add backend/src/lib/types.ts backend/src/routes/config.ts src/lib/vault-types.ts src/lib/api.ts
git commit -m "feat: add authMode to VaultConfig and status endpoint"
```

---

### Task 3: Create UserStore

**Files:**
- Create: `backend/src/lib/users.ts`

- [ ] **Step 1: Write the UserStore class**

```typescript
import { readFileSync, writeFileSync, existsSync, mkdirSync } from 'node:fs';
import { dirname } from 'node:path';
import { randomBytes } from 'node:crypto';

export type Role = 'admin' | 'user';

export interface User {
  address: string;   // 0x + hex(SHA256(mldsaPubKey)) — NOT p2tr/tweakedPubKey
  role: Role;
  label: string;
}

export interface Invite {
  code: string;
  role: Role;
  usesLeft: number;
  expiresAt: number;  // unix ms
}

interface UserDB {
  users: User[];
  invites: Invite[];
  settings: { everybodyCanRead: boolean };
}

const DATA_DIR = process.env.DATA_DIR || '/data';
const USERS_PATH = `${DATA_DIR}/users.json`;

export class UserStore {
  private db: UserDB = { users: [], invites: [], settings: { everybodyCanRead: true } };

  constructor() {
    this.load();
  }

  private load(): void {
    if (!existsSync(USERS_PATH)) return;
    try {
      this.db = JSON.parse(readFileSync(USERS_PATH, 'utf8'));
    } catch { /* corrupt or missing — start fresh */ }
  }

  private save(): void {
    mkdirSync(dirname(USERS_PATH), { recursive: true });
    writeFileSync(USERS_PATH, JSON.stringify(this.db, null, 2));
  }

  hasUsers(): boolean {
    return this.db.users.length > 0;
  }

  // ── Users ──

  getUser(address: string): User | null {
    return this.db.users.find(u => u.address === address) ?? null;
  }

  addUser(address: string, role: Role, label: string): User {
    if (this.getUser(address)) throw new Error('User already exists');
    const user: User = { address, role, label };
    this.db.users.push(user);
    this.save();
    return user;
  }

  removeUser(address: string): void {
    const before = this.db.users.length;
    this.db.users = this.db.users.filter(u => u.address !== address);
    if (this.db.users.length === before) throw new Error('User not found');
    this.save();
  }

  updateRole(address: string, role: Role): void {
    const user = this.getUser(address);
    if (!user) throw new Error('User not found');
    user.role = role;
    this.save();
  }

  listUsers(): User[] {
    return [...this.db.users];
  }

  // ── Invites ──

  createInvite(role: Role, maxUses: number, expiresAt: number): Invite {
    const code = randomBytes(3).toString('hex').toUpperCase();
    const invite: Invite = { code, role, usesLeft: maxUses, expiresAt };
    this.db.invites.push(invite);
    this.save();
    return invite;
  }

  redeemInvite(code: string, address: string, label: string): User | null {
    const invite = this.db.invites.find(i => i.code === code);
    if (!invite) return null;
    if (Date.now() > invite.expiresAt) return null;
    if (invite.usesLeft <= 0) return null;
    if (this.getUser(address)) return null; // already registered

    invite.usesLeft--;
    if (invite.usesLeft <= 0) {
      this.db.invites = this.db.invites.filter(i => i.code !== code);
    }
    const user = { address, role: invite.role, label };
    this.db.users.push(user);
    this.save();
    return user;
  }

  listInvites(): Invite[] {
    // Clean expired
    const now = Date.now();
    this.db.invites = this.db.invites.filter(i => i.expiresAt > now && i.usesLeft > 0);
    return [...this.db.invites];
  }

  removeInvite(code: string): void {
    this.db.invites = this.db.invites.filter(i => i.code !== code);
    this.save();
  }

  // ── Settings ──

  getEverybodyCanRead(): boolean {
    return this.db.settings.everybodyCanRead;
  }

  setEverybodyCanRead(value: boolean): void {
    this.db.settings.everybodyCanRead = value;
    this.save();
  }
}
```

- [ ] **Step 2: Verify it compiles**

Run: `cd backend && npx tsc`

- [ ] **Step 3: Commit**

```bash
git add backend/src/lib/users.ts
git commit -m "feat: UserStore — file-based user and invite management"
```

---

### Task 4: Rewrite auth.ts — ML-DSA verification + role-aware middleware

**Files:**
- Rewrite: `backend/src/lib/auth.ts`

- [ ] **Step 1: Rewrite auth.ts with challenge store, ML-DSA verify, and role middleware**

```typescript
import { createHash, randomBytes, scryptSync, timingSafeEqual } from 'node:crypto';
import type { Request, Response, NextFunction, RequestHandler } from 'express';
import { ml_dsa44, ml_dsa65, ml_dsa87 } from '@btc-vision/post-quantum/ml-dsa.js';
import type { ConfigStore } from './config-store.js';
import type { UserStore, Role } from './users.js';

// ── Password hashing (for password auth mode) ──

const SCRYPT_KEYLEN = 64;

export function hashPassword(password: string): string {
  const salt = randomBytes(16).toString('hex');
  const hash = scryptSync(password, salt, SCRYPT_KEYLEN).toString('hex');
  return `${salt}:${hash}`;
}

export function verifyPassword(password: string, stored: string): boolean {
  const [salt, hash] = stored.split(':');
  if (!salt || !hash) return false;
  const computed = scryptSync(password, salt, SCRYPT_KEYLEN).toString('hex');
  return timingSafeEqual(Buffer.from(hash), Buffer.from(computed));
}

// ── Token management ──

interface TokenInfo {
  expiresAt: number;
  role: 'admin' | 'user' | 'password-admin'; // password-admin = legacy password mode
  address?: string; // wallet address (only for wallet mode)
}

const tokens = new Map<string, TokenInfo>();
const TOKEN_EXPIRY = 60 * 60 * 1000; // 1 hour

export function createToken(role: TokenInfo['role'], address?: string): string {
  const token = randomBytes(32).toString('hex');
  tokens.set(token, { expiresAt: Date.now() + TOKEN_EXPIRY, role, address });
  return token;
}

export function getTokenInfo(token: string): TokenInfo | null {
  const info = tokens.get(token);
  if (!info) return null;
  if (Date.now() > info.expiresAt) {
    tokens.delete(token);
    return null;
  }
  return info;
}

// ── Challenge management ──

interface Challenge {
  value: string;
  expiresAt: number;
}

const challenges = new Map<string, Challenge>();
const CHALLENGE_EXPIRY = 60_000; // 60 seconds

export function createChallenge(): string {
  const value = randomBytes(32).toString('hex');
  challenges.set(value, { value, expiresAt: Date.now() + CHALLENGE_EXPIRY });
  return value;
}

export function consumeChallenge(value: string): boolean {
  const c = challenges.get(value);
  if (!c) return false;
  challenges.delete(value); // one-use
  return Date.now() <= c.expiresAt;
}

// ── ML-DSA verification ──
// CRITICAL: this uses mldsaPubKey (1312/1952/2592 bytes), NOT p2tr/tweakedPubKey

interface MLDSALevel {
  sigSize: number;
  verify: (sig: Uint8Array, msg: Uint8Array, publicKey: Uint8Array) => boolean;
  name: string;
}

const MLDSA_LEVELS: ReadonlyMap<number, MLDSALevel> = new Map([
  [1312, { sigSize: 2420, verify: ml_dsa44.verify, name: 'ML-DSA-44' }],
  [1952, { sigSize: 3309, verify: ml_dsa65.verify, name: 'ML-DSA-65' }],
  [2592, { sigSize: 4627, verify: ml_dsa87.verify, name: 'ML-DSA-87' }],
]);

export function verifyMLDSA(
  signature: Uint8Array,
  mldsaPubKey: Uint8Array,
  challenge: string,
): { valid: boolean; walletAddress?: string; error?: string } {
  const level = MLDSA_LEVELS.get(mldsaPubKey.length);
  if (!level) return { valid: false, error: `unrecognized ML-DSA public key size: ${mldsaPubKey.length}` };
  if (signature.length !== level.sigSize) {
    return { valid: false, error: `signature size ${signature.length} doesn't match ${level.name} (expected ${level.sigSize})` };
  }

  // Reconstruct double-hash per OPWallet convention:
  // signedData = SHA256(hex(SHA256("PERMAFROST auth {challenge}")))
  const message = `PERMAFROST auth ${challenge}`;
  const messageHash = createHash('sha256').update(message).digest();
  const walletInput = messageHash.toString('hex');
  const signedHash = createHash('sha256').update(walletInput).digest();

  let isValid: boolean;
  try {
    isValid = level.verify(
      new Uint8Array(signature),
      new Uint8Array(signedHash),
      new Uint8Array(mldsaPubKey),
    );
  } catch (err) {
    return { valid: false, error: `${level.name} verify error: ${err instanceof Error ? err.message : String(err)}` };
  }

  if (!isValid) return { valid: false, error: 'signature verification failed' };

  // Wallet address = 0x + hex(SHA256(mldsaPubKey)) — NOT tweakedPubKey
  const walletAddress = '0x' + createHash('sha256').update(mldsaPubKey).digest('hex');
  return { valid: true, walletAddress };
}

// ── Role-aware middleware ──

function extractToken(req: Request): string | null {
  const auth = req.headers.authorization;
  if (!auth?.startsWith('Bearer ')) return null;
  return auth.slice(7);
}

export interface AuthMiddleware {
  requireAdmin: RequestHandler;
  requireUser: RequestHandler;
  requireRead: RequestHandler;
}

export function createAuthMiddleware(store: ConfigStore, userStore: UserStore): AuthMiddleware {
  function getAuthMode(): 'password' | 'wallet' {
    try {
      return store.get().authMode || 'password';
    } catch {
      return 'password';
    }
  }

  function isConfigLoaded(): boolean {
    try { store.get(); return true; } catch { return false; }
  }

  const requireAdmin: RequestHandler = (req: Request, res: Response, next: NextFunction): void => {
    if (!isConfigLoaded()) { next(); return; }
    const mode = getAuthMode();

    if (mode === 'password') {
      // Legacy: check admin password token, skip if no password set
      try {
        const config = store.get();
        if (!config.adminPasswordHash) { next(); return; }
      } catch { next(); return; }

      const token = extractToken(req);
      if (!token) { res.status(401).json({ error: 'Admin authentication required' }); return; }
      const info = getTokenInfo(token);
      if (!info) { res.status(401).json({ error: 'Invalid or expired token' }); return; }
      if (info.role !== 'password-admin') { res.status(403).json({ error: 'Admin role required' }); return; }
      next();
      return;
    }

    // Wallet mode
    const token = extractToken(req);
    if (!token) { res.status(401).json({ error: 'Authentication required' }); return; }
    const info = getTokenInfo(token);
    if (!info) { res.status(401).json({ error: 'Invalid or expired token' }); return; }
    if (info.role !== 'admin') { res.status(403).json({ error: 'Admin role required' }); return; }
    next();
  };

  const requireUser: RequestHandler = (req: Request, res: Response, next: NextFunction): void => {
    if (!isConfigLoaded()) { next(); return; }
    const mode = getAuthMode();

    if (mode === 'password') {
      // Password mode: requireUser acts like requireAdmin (same token)
      requireAdmin(req, res, next);
      return;
    }

    // Wallet mode: admin or user
    const token = extractToken(req);
    if (!token) { res.status(401).json({ error: 'Authentication required' }); return; }
    const info = getTokenInfo(token);
    if (!info) { res.status(401).json({ error: 'Invalid or expired token' }); return; }
    if (info.role !== 'admin' && info.role !== 'user') {
      res.status(403).json({ error: 'User or admin role required' });
      return;
    }
    next();
  };

  const requireRead: RequestHandler = (req: Request, res: Response, next: NextFunction): void => {
    if (!isConfigLoaded()) { next(); return; }
    const mode = getAuthMode();

    if (mode === 'password') { next(); return; } // reads always allowed in password mode

    // Wallet mode: check everybodyCanRead setting
    if (userStore.getEverybodyCanRead()) { next(); return; }

    // Need at least a valid token (any role)
    const token = extractToken(req);
    if (!token) { res.status(401).json({ error: 'Authentication required' }); return; }
    const info = getTokenInfo(token);
    if (!info) { res.status(401).json({ error: 'Invalid or expired token' }); return; }
    next();
  };

  return { requireAdmin, requireUser, requireRead };
}
```

- [ ] **Step 2: Verify it compiles**

Run: `cd backend && npx tsc`

- [ ] **Step 3: Commit**

```bash
git add backend/src/lib/auth.ts
git commit -m "feat: auth.ts — ML-DSA verification, challenges, role middleware"
```

---

### Task 5: Create auth routes

**Files:**
- Create: `backend/src/routes/auth.ts`

- [ ] **Step 1: Write auth route handlers**

```typescript
import { Router, type Request, type Response } from 'express';
import {
  createChallenge, consumeChallenge,
  verifyMLDSA, createToken, getTokenInfo,
} from '../lib/auth.js';
import type { UserStore } from '../lib/users.js';

const BASE64_RE = /^[A-Za-z0-9+/]+=*$/;

function decodeBase64(str: string): Uint8Array | null {
  if (!str || !BASE64_RE.test(str)) return null;
  const buf = Buffer.from(str, 'base64');
  return buf.length > 0 ? new Uint8Array(buf) : null;
}

export function authRoutes(userStore: UserStore): Router {
  const r = Router();

  /** GET /api/auth/challenge — generate one-use challenge */
  r.get('/challenge', (_req: Request, res: Response) => {
    const challenge = createChallenge();
    res.json({ challenge });
  });

  /** POST /api/auth/verify — verify ML-DSA sig, return token + role */
  r.post('/verify', (req: Request, res: Response) => {
    const { challenge, signature, publicKey } = req.body as {
      challenge?: string;
      signature?: string;  // base64-encoded ML-DSA sig
      publicKey?: string;  // base64-encoded ML-DSA pubkey (NOT tweakedPubKey)
    };

    if (!challenge || !signature || !publicKey) {
      res.status(400).json({ error: 'challenge, signature, and publicKey required' });
      return;
    }

    if (!consumeChallenge(challenge)) {
      res.status(400).json({ error: 'Invalid or expired challenge' });
      return;
    }

    const sigBytes = decodeBase64(signature);
    const pubKeyBytes = decodeBase64(publicKey);
    if (!sigBytes) { res.status(400).json({ error: 'Invalid base64 in signature' }); return; }
    if (!pubKeyBytes) { res.status(400).json({ error: 'Invalid base64 in publicKey' }); return; }

    const result = verifyMLDSA(sigBytes, pubKeyBytes, challenge);
    if (!result.valid || !result.walletAddress) {
      res.status(401).json({ error: result.error || 'Verification failed' });
      return;
    }

    const user = userStore.getUser(result.walletAddress);
    if (!user) {
      res.json({ authenticated: false, needsInvite: true, address: result.walletAddress });
      return;
    }

    const token = createToken(user.role, user.address);
    res.json({ authenticated: true, token, role: user.role, address: user.address, label: user.label });
  });

  /** POST /api/auth/redeem — verify sig + use invite code to register */
  r.post('/redeem', (req: Request, res: Response) => {
    const { challenge, signature, publicKey, inviteCode, label } = req.body as {
      challenge?: string;
      signature?: string;
      publicKey?: string;
      inviteCode?: string;
      label?: string;
    };

    if (!challenge || !signature || !publicKey || !inviteCode) {
      res.status(400).json({ error: 'challenge, signature, publicKey, and inviteCode required' });
      return;
    }

    if (!consumeChallenge(challenge)) {
      res.status(400).json({ error: 'Invalid or expired challenge' });
      return;
    }

    const sigBytes = decodeBase64(signature);
    const pubKeyBytes = decodeBase64(publicKey);
    if (!sigBytes || !pubKeyBytes) {
      res.status(400).json({ error: 'Invalid base64 encoding' });
      return;
    }

    const result = verifyMLDSA(sigBytes, pubKeyBytes, challenge);
    if (!result.valid || !result.walletAddress) {
      res.status(401).json({ error: result.error || 'Verification failed' });
      return;
    }

    const user = userStore.redeemInvite(inviteCode, result.walletAddress, label || result.walletAddress.slice(0, 10));
    if (!user) {
      res.status(400).json({ error: 'Invalid, expired, or exhausted invite code' });
      return;
    }

    const token = createToken(user.role, user.address);
    res.json({ authenticated: true, token, role: user.role, address: user.address, label: user.label });
  });

  /** GET /api/auth/me — return current session info */
  r.get('/me', (req: Request, res: Response) => {
    const auth = req.headers.authorization;
    if (!auth?.startsWith('Bearer ')) {
      res.json({ authenticated: false });
      return;
    }
    const info = getTokenInfo(auth.slice(7));
    if (!info) {
      res.json({ authenticated: false });
      return;
    }
    res.json({ authenticated: true, role: info.role, address: info.address });
  });

  return r;
}
```

- [ ] **Step 2: Verify it compiles**

Run: `cd backend && npx tsc`

- [ ] **Step 3: Commit**

```bash
git add backend/src/routes/auth.ts
git commit -m "feat: auth routes — challenge, verify, redeem, /me"
```

---

### Task 6: Create user/invite CRUD routes

**Files:**
- Create: `backend/src/routes/users.ts`

- [ ] **Step 1: Write user and invite admin routes**

```typescript
import { Router, type Request, type Response, type RequestHandler } from 'express';
import type { UserStore, Role } from '../lib/users.js';

export function userRoutes(userStore: UserStore, requireAdmin: RequestHandler): Router {
  const r = Router();

  // ── Users ──

  r.get('/', requireAdmin, (_req: Request, res: Response) => {
    res.json({ users: userStore.listUsers() });
  });

  r.post('/', requireAdmin, (req: Request, res: Response) => {
    const { address, role, label } = req.body as { address?: string; role?: Role; label?: string };
    if (!address || !role || !label) {
      res.status(400).json({ error: 'address, role, and label required' });
      return;
    }
    if (role !== 'admin' && role !== 'user') {
      res.status(400).json({ error: 'role must be "admin" or "user"' });
      return;
    }
    try {
      const user = userStore.addUser(address, role, label);
      res.json({ ok: true, user });
    } catch (e) {
      res.status(409).json({ error: (e as Error).message });
    }
  });

  r.delete('/:address', requireAdmin, (req: Request, res: Response) => {
    try {
      userStore.removeUser(req.params.address!);
      res.json({ ok: true });
    } catch (e) {
      res.status(404).json({ error: (e as Error).message });
    }
  });

  r.patch('/:address', requireAdmin, (req: Request, res: Response) => {
    const { role } = req.body as { role?: Role };
    if (!role || (role !== 'admin' && role !== 'user')) {
      res.status(400).json({ error: 'role must be "admin" or "user"' });
      return;
    }
    try {
      userStore.updateRole(req.params.address!, role);
      res.json({ ok: true });
    } catch (e) {
      res.status(404).json({ error: (e as Error).message });
    }
  });

  return r;
}

export function inviteRoutes(userStore: UserStore, requireAdmin: RequestHandler): Router {
  const r = Router();

  r.get('/', requireAdmin, (_req: Request, res: Response) => {
    res.json({ invites: userStore.listInvites() });
  });

  r.post('/', requireAdmin, (req: Request, res: Response) => {
    const { role, maxUses, expiresAt } = req.body as {
      role?: Role; maxUses?: number; expiresAt?: number;
    };
    if (!maxUses || !expiresAt) {
      res.status(400).json({ error: 'maxUses and expiresAt required' });
      return;
    }
    const invite = userStore.createInvite(role || 'user', maxUses, expiresAt);
    res.json({ ok: true, invite });
  });

  r.delete('/:code', requireAdmin, (req: Request, res: Response) => {
    userStore.removeInvite(req.params.code!);
    res.json({ ok: true });
  });

  // ── Everybody visibility setting ──

  r.get('/settings/visibility', requireAdmin, (_req: Request, res: Response) => {
    res.json({ everybodyCanRead: userStore.getEverybodyCanRead() });
  });

  r.post('/settings/visibility', requireAdmin, (req: Request, res: Response) => {
    const { everybodyCanRead } = req.body as { everybodyCanRead?: boolean };
    if (typeof everybodyCanRead !== 'boolean') {
      res.status(400).json({ error: 'everybodyCanRead must be a boolean' });
      return;
    }
    userStore.setEverybodyCanRead(everybodyCanRead);
    res.json({ ok: true });
  });

  return r;
}
```

- [ ] **Step 2: Verify it compiles**

Run: `cd backend && npx tsc`

- [ ] **Step 3: Commit**

```bash
git add backend/src/routes/users.ts
git commit -m "feat: user/invite CRUD routes + visibility toggle"
```

---

### Task 7: Update server.ts and existing routes for role middleware

**Files:**
- Modify: `backend/src/server.ts`
- Modify: `backend/src/routes/config.ts`
- Modify: `backend/src/routes/wallet.ts`
- Modify: `backend/src/routes/tx.ts`
- Modify: `backend/src/routes/hosting.ts`
- Modify: `backend/src/routes/balances.ts`

- [ ] **Step 1: Update server.ts**

Replace current middleware setup and route registration:

```typescript
import express from 'express';
import { createProxyMiddleware } from 'http-proxy-middleware';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { ConfigStore } from './lib/config-store.js';
import { UserStore } from './lib/users.js';
import { createAuthMiddleware } from './lib/auth.js';
import { configRoutes } from './routes/config.js';
import { authRoutes } from './routes/auth.js';
import { userRoutes, inviteRoutes } from './routes/users.js';
import { walletRoutes } from './routes/wallet.js';
import { txRoutes } from './routes/tx.js';
import { balanceRoutes } from './routes/balances.js';
import { hostingRoutes } from './routes/hosting.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const PORT = parseInt(process.env.PORT || '8080', 10);
const RELAY_PORT = parseInt(process.env.RELAY_PORT || '8081', 10);

const store = new ConfigStore();
const userStore = new UserStore();
const app = express();

app.use(express.json({ limit: '10mb' }));

// Try to auto-load persistent config on startup
try { store.load(); } catch { /* not initialized or encrypted — that's fine */ }

// Auth middleware (role-aware, supports both password and wallet modes)
const { requireAdmin, requireUser, requireRead } = createAuthMiddleware(store, userStore);

// API routes
app.use('/api', configRoutes(store, userStore, requireAdmin));
app.use('/api/auth', authRoutes(userStore));
app.use('/api/users', userRoutes(userStore, requireAdmin));
app.use('/api/invites', inviteRoutes(userStore, requireAdmin));
app.use('/api/wallet', walletRoutes(store, requireAdmin));
app.use('/api/tx', txRoutes(store, requireUser, requireAdmin));
app.use('/api/balances', balanceRoutes(store, requireRead));
app.use('/api/hosting', hostingRoutes(store, requireAdmin, requireRead));

// Proxy WebSocket to relay
const wsProxy = createProxyMiddleware({
  target: `http://127.0.0.1:${RELAY_PORT}`,
  ws: true,
  changeOrigin: true,
});
app.use('/ws', wsProxy);

// Serve frontend static files
const distDir = join(__dirname, '..', 'dist');
app.use(express.static(distDir));
app.get('*', (_req, res) => {
  res.sendFile(join(distDir, 'index.html'));
});

const server = app.listen(PORT, () => {
  console.log(`permafrost-vault backend listening on :${PORT}`);
});

server.on('upgrade', wsProxy.upgrade);

export { store };
```

- [ ] **Step 2: Update config routes signature**

In `backend/src/routes/config.ts`, change the function signature to accept `userStore`:

```typescript
import type { UserStore } from '../lib/users.js';

export function configRoutes(store: ConfigStore, userStore: UserStore, requireAdmin: RequestHandler): Router {
```

Update `POST /api/init` to accept `authMode` and handle wallet mode (first admin auto-registration):

In the init handler body, after `adminPassword` validation, add `authMode` handling:
```typescript
const { network, storageMode, password, adminPassword, authMode, walletAddress, walletLabel } = req.body as {
  network: NetworkName;
  storageMode: StorageMode;
  password?: string;
  adminPassword?: string;
  authMode?: 'password' | 'wallet';
  walletAddress?: string;
  walletLabel?: string;
};

// ... network/storageMode validation unchanged ...

const resolvedAuthMode = authMode || 'password';

if (resolvedAuthMode === 'password') {
  if (!adminPassword) {
    res.status(400).json({ error: 'adminPassword required' });
    return;
  }
} else {
  if (!walletAddress) {
    res.status(400).json({ error: 'walletAddress required for wallet auth mode' });
    return;
  }
}

try {
  store.init(network, storageMode, password);

  if (resolvedAuthMode === 'password') {
    store.update({ adminPasswordHash: hashPassword(adminPassword!), authMode: 'password' }, password);
  } else {
    store.update({ authMode: 'wallet' }, password);
    userStore.addUser(walletAddress!, 'admin', walletLabel || 'Admin');
  }

  res.json({ ok: true });
} catch (e) {
  res.status(409).json({ error: (e as Error).message });
}
```

Update the `POST /api/admin/unlock` handler to return `password-admin` role tokens:
```typescript
const token = createToken('password-admin');
```

- [ ] **Step 3: Update tx routes — accept requireUser**

Change signature:
```typescript
export function txRoutes(store: ConfigStore, requireUser: RequestHandler, requireAdmin: RequestHandler): Router {
```

Change `encode` and `simulate` to use `requireUser`:
```typescript
r.post('/encode', requireUser, (req, res) => { ... });
r.post('/simulate', requireUser, (req, res) => { ... });
```

Keep `broadcast` using `requireUser` (was `requireAdmin` — users should be able to broadcast):
```typescript
r.post('/broadcast', requireUser, async (req, res) => { ... });
```

- [ ] **Step 4: Update balances routes — accept requireRead**

Change signature:
```typescript
export function balanceRoutes(store: ConfigStore, requireRead: RequestHandler): Router {
```

Add `requireRead` to GET:
```typescript
r.get('/', requireRead, async (_req, res) => { ... });
```

- [ ] **Step 5: Update hosting routes — accept requireRead**

Change signature:
```typescript
export function hostingRoutes(store: ConfigStore, requireAdmin: RequestHandler, requireRead: RequestHandler): Router {
```

Add `requireRead` to GET:
```typescript
r.get('/', requireRead, (_req, res) => { ... });
```

- [ ] **Step 6: Verify everything compiles**

Run: `cd backend && npx tsc`

- [ ] **Step 7: Commit**

```bash
git add backend/src/server.ts backend/src/routes/config.ts backend/src/routes/wallet.ts \
       backend/src/routes/tx.ts backend/src/routes/hosting.ts backend/src/routes/balances.ts
git commit -m "feat: role-aware middleware across all routes"
```

---

## Chunk 2: Frontend — Wallet Auth, Role Context, UI

### Task 8: Add auth API endpoints to frontend

**Files:**
- Modify: `src/lib/api.ts`

- [ ] **Step 1: Add auth endpoints and rename token storage to be mode-agnostic**

Rename `ADMIN_TOKEN_KEY` to `SESSION_TOKEN_KEY`. Add:

```typescript
const SESSION_TOKEN_KEY = 'permafrost-session-token';
const SESSION_ROLE_KEY = 'permafrost-session-role';

// ... update getAdminToken/setAdminToken/clearAdminToken/hasAdminToken to use SESSION_TOKEN_KEY ...

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
```

Add auth endpoints:
```typescript
// ── Wallet Auth ──

export const getChallenge = () =>
  json<{ challenge: string }>('/auth/challenge');

export const verifyAuth = (challenge: string, signature: string, publicKey: string) =>
  json<{ authenticated: boolean; needsInvite?: boolean; token?: string; role?: string; address?: string; label?: string }>('/auth/verify', {
    method: 'POST',
    body: JSON.stringify({ challenge, signature, publicKey }),
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
```

- [ ] **Step 2: Update initInstance to accept authMode + walletAddress**

```typescript
export const initInstance = (
  network: NetworkName,
  storageMode: StorageMode,
  password?: string,
  adminPassword?: string,
  authMode?: 'password' | 'wallet',
  walletAddress?: string,
  walletLabel?: string,
) =>
  json<{ ok: true }>('/init', {
    method: 'POST',
    body: JSON.stringify({ network, storageMode, password, adminPassword, authMode, walletAddress, walletLabel }),
  });
```

- [ ] **Step 3: Verify frontend compiles**

Run: `npx tsc -b`

- [ ] **Step 4: Commit**

```bash
git add src/lib/api.ts
git commit -m "feat: auth, user, invite API endpoints + role session storage"
```

---

### Task 9: Create WalletAuth component

**Files:**
- Create: `src/components/WalletAuth.tsx`

- [ ] **Step 1: Write the wallet connect + challenge-response component**

```typescript
import { useState, useCallback } from 'react';
import { getChallenge, verifyAuth, redeemInvite, setAdminToken, setSessionRole } from '../lib/api';
import { OtziWordmark } from '../App';

interface OPNetWallet {
  requestAccounts(): Promise<string[]>;
  web3: {
    signMLDSAMessage(messageHex: string): Promise<{ signature: string; publicKey: string }>;
  };
}

declare global {
  interface Window {
    opnet?: OPNetWallet;
  }
}

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

function hexToBytes(hex: string): Uint8Array {
  if (hex.startsWith('0x')) hex = hex.slice(2);
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) bytes[i] = parseInt(hex.substr(i * 2, 2), 16);
  return bytes;
}

function uint8ToBase64(bytes: Uint8Array): string {
  let binary = '';
  for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]!);
  return btoa(binary);
}

interface Props {
  onAuthenticated: (role: string, address: string) => void;
}

export function WalletAuth({ onAuthenticated }: Props) {
  const [step, setStep] = useState<'connect' | 'signing' | 'invite'>('connect');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  const [walletAddress, setWalletAddress] = useState('');
  const [inviteCode, setInviteCode] = useState('');
  const [inviteLabel, setInviteLabel] = useState('');

  // Store challenge + signed data for invite redemption
  const [pendingAuth, setPendingAuth] = useState<{
    challenge: string;
    signature: string;
    publicKey: string;
  } | null>(null);

  const signChallenge = useCallback(async () => {
    const wallet = window.opnet;
    if (!wallet) {
      setError('OPWallet not detected. Install the OPWallet browser extension.');
      return null;
    }

    // Get challenge from server
    const { challenge } = await getChallenge();

    // Construct message and double-hash per OPWallet convention
    const message = `PERMAFROST auth ${challenge}`;
    const msgBytes = new TextEncoder().encode(message);
    const hashBuf = await crypto.subtle.digest('SHA-256', msgBytes);
    const messageHex = bytesToHex(new Uint8Array(hashBuf));

    // Sign with ML-DSA via OPWallet
    const signed = await wallet.web3.signMLDSAMessage(messageHex);

    // Convert hex sig/pubkey to base64 for the backend
    const signature = uint8ToBase64(hexToBytes(signed.signature));
    const publicKey = uint8ToBase64(hexToBytes(signed.publicKey));

    return { challenge, signature, publicKey };
  }, []);

  const handleConnect = async () => {
    setError('');
    setLoading(true);
    try {
      const wallet = window.opnet;
      if (!wallet) {
        setError('OPWallet not detected. Install the OPWallet browser extension.');
        return;
      }

      const accounts = await wallet.requestAccounts();
      if (!accounts?.length) { setError('No accounts returned'); return; }
      setWalletAddress(accounts[0]!);
      setStep('signing');

      const auth = await signChallenge();
      if (!auth) return;

      const result = await verifyAuth(auth.challenge, auth.signature, auth.publicKey);

      if (result.authenticated && result.token && result.role) {
        setAdminToken(result.token);
        setSessionRole(result.role);
        onAuthenticated(result.role, result.address || '');
      } else if (result.needsInvite) {
        setPendingAuth(auth);
        setStep('invite');
      } else {
        setError('Authentication failed');
        setStep('connect');
      }
    } catch (e) {
      setError((e as Error).message);
      setStep('connect');
    } finally {
      setLoading(false);
    }
  };

  const handleRedeem = async () => {
    if (!inviteCode) return;
    setError('');
    setLoading(true);
    try {
      // Need a fresh challenge + signature for the redeem call
      const auth = await signChallenge();
      if (!auth) return;

      const result = await redeemInvite(
        auth.challenge, auth.signature, auth.publicKey,
        inviteCode, inviteLabel || undefined,
      );

      if (result.authenticated && result.token && result.role) {
        setAdminToken(result.token);
        setSessionRole(result.role);
        onAuthenticated(result.role, result.address || '');
      } else {
        setError('Invalid, expired, or exhausted invite code');
      }
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="ceremony">
      <div style={{ textAlign: 'center', marginBottom: 8 }}>
        <OtziWordmark height={48} />
      </div>

      {step === 'connect' && (
        <div className="card" style={{ textAlign: 'center' }}>
          <p style={{ marginBottom: 16 }}>Connect your OPWallet to authenticate</p>
          {error && <div className="warning" style={{ marginBottom: 12 }}>{error}</div>}
          <button className="btn btn-primary btn-full" onClick={handleConnect} disabled={loading}>
            {loading ? <span className="spinner" /> : 'Connect OPWallet'}
          </button>
        </div>
      )}

      {step === 'signing' && (
        <div className="card" style={{ textAlign: 'center' }}>
          <div className="spinner" style={{ margin: '0 auto 16px' }} />
          <p>Signing challenge with OPWallet...</p>
          <p style={{ fontSize: 12, color: 'var(--white-dim)', fontFamily: 'monospace' }}>{walletAddress}</p>
        </div>
      )}

      {step === 'invite' && (
        <div className="card">
          <h2>Invite Code Required</h2>
          <p style={{ fontSize: 13, color: 'var(--white-dim)', marginBottom: 16 }}>
            Your wallet is not registered. Enter an invite code to gain access.
          </p>
          <div className="form-row">
            <label>
              Invite Code
              <input
                autoFocus
                value={inviteCode}
                onChange={e => setInviteCode(e.target.value.toUpperCase())}
                placeholder="e.g. X7K2M9"
                style={{ fontFamily: 'monospace', textTransform: 'uppercase' }}
              />
            </label>
          </div>
          <div className="form-row">
            <label>
              Display Name (optional)
              <input
                value={inviteLabel}
                onChange={e => setInviteLabel(e.target.value)}
                placeholder="Your name"
              />
            </label>
          </div>
          {error && <div className="warning" style={{ marginBottom: 12 }}>{error}</div>}
          <div style={{ display: 'flex', gap: 12 }}>
            <button className="btn btn-secondary" onClick={() => { setStep('connect'); setError(''); }}>Back</button>
            <button className="btn btn-primary" style={{ flex: 1 }} onClick={handleRedeem} disabled={loading || !inviteCode}>
              {loading ? <span className="spinner" /> : 'Submit'}
            </button>
          </div>
        </div>
      )}
    </div>
  );
}
```

- [ ] **Step 2: Verify it compiles**

Run: `npx tsc -b`

- [ ] **Step 3: Commit**

```bash
git add src/components/WalletAuth.tsx
git commit -m "feat: WalletAuth component — OPWallet connect + ML-DSA challenge-response"
```

---

### Task 10: Create UserManager component

**Files:**
- Create: `src/components/UserManager.tsx`

- [ ] **Step 1: Write the user/invite management component for Settings**

```typescript
import { useState, useEffect } from 'react';
import { listUsers, addUser, removeUser, updateUserRole, listInvites, createInvite, deleteInvite, getVisibility, setVisibility } from '../lib/api';

interface User { address: string; role: string; label: string }
interface Invite { code: string; role: string; usesLeft: number; expiresAt: number }

export function UserManager() {
  const [users, setUsers] = useState<User[]>([]);
  const [invites, setInvites] = useState<Invite[]>([]);
  const [everybodyCanRead, setEverybodyCanRead] = useState(true);
  const [error, setError] = useState('');

  // Add user form
  const [newAddress, setNewAddress] = useState('');
  const [newRole, setNewRole] = useState<'admin' | 'user'>('user');
  const [newLabel, setNewLabel] = useState('');

  // Create invite form
  const [inviteMaxUses, setInviteMaxUses] = useState(3);
  const [inviteExpiryHours, setInviteExpiryHours] = useState(24);

  useEffect(() => {
    listUsers().then(r => setUsers(r.users)).catch(() => {});
    listInvites().then(r => setInvites(r.invites)).catch(() => {});
    getVisibility().then(r => setEverybodyCanRead(r.everybodyCanRead)).catch(() => {});
  }, []);

  const handleAddUser = async () => {
    if (!newAddress.trim() || !newLabel.trim()) return;
    try {
      await addUser(newAddress.trim(), newRole, newLabel.trim());
      setUsers(await listUsers().then(r => r.users));
      setNewAddress(''); setNewLabel(''); setError('');
    } catch (e) { setError((e as Error).message); }
  };

  const handleRemove = async (address: string) => {
    try {
      await removeUser(address);
      setUsers(prev => prev.filter(u => u.address !== address));
    } catch (e) { setError((e as Error).message); }
  };

  const handleRoleChange = async (address: string, role: string) => {
    try {
      await updateUserRole(address, role);
      setUsers(prev => prev.map(u => u.address === address ? { ...u, role } : u));
    } catch (e) { setError((e as Error).message); }
  };

  const handleCreateInvite = async () => {
    try {
      const expiresAt = Date.now() + inviteExpiryHours * 60 * 60 * 1000;
      await createInvite(inviteMaxUses, expiresAt);
      setInvites(await listInvites().then(r => r.invites));
    } catch (e) { setError((e as Error).message); }
  };

  const handleDeleteInvite = async (code: string) => {
    try {
      await deleteInvite(code);
      setInvites(prev => prev.filter(i => i.code !== code));
    } catch (e) { setError((e as Error).message); }
  };

  const handleVisibilityToggle = async () => {
    const newVal = !everybodyCanRead;
    try {
      await setVisibility(newVal);
      setEverybodyCanRead(newVal);
    } catch (e) { setError((e as Error).message); }
  };

  return (
    <>
      {error && <div className="warning" style={{ marginBottom: 12 }}>{error}</div>}

      {/* Visibility toggle */}
      <div className="card">
        <h2>Public Visibility</h2>
        <label style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: 14, cursor: 'pointer' }}>
          <input type="checkbox" checked={everybodyCanRead} onChange={handleVisibilityToggle} />
          Allow unauthenticated visitors to view dashboard and settings (read-only)
        </label>
      </div>

      {/* Users */}
      <div className="card">
        <h2>Users</h2>
        {users.length === 0 && <p style={{ color: 'var(--white-dim)', fontSize: 13 }}>No users registered.</p>}
        {users.map(u => (
          <div key={u.address} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '8px 0', borderBottom: '1px solid var(--gray-dark)' }}>
            <div>
              <strong style={{ fontSize: 14 }}>{u.label}</strong>
              <div style={{ fontSize: 11, fontFamily: 'monospace', color: 'var(--white-dim)', marginTop: 2 }}>{u.address.slice(0, 18)}...</div>
            </div>
            <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
              <select value={u.role} onChange={e => handleRoleChange(u.address, e.target.value)} style={{ fontSize: 12, padding: '4px 8px' }}>
                <option value="admin">Admin</option>
                <option value="user">User</option>
              </select>
              <button className="btn btn-secondary" style={{ fontSize: 12, padding: '4px 10px', color: 'var(--red)' }} onClick={() => handleRemove(u.address)}>
                Remove
              </button>
            </div>
          </div>
        ))}

        <div style={{ marginTop: 16, paddingTop: 16, borderTop: '1px solid var(--gray-dark)' }}>
          <h3 style={{ fontSize: 14, marginBottom: 8 }}>Add User</h3>
          <div className="form-row">
            <label>
              Wallet Address (0x...)
              <input value={newAddress} onChange={e => setNewAddress(e.target.value)} placeholder="0x..." style={{ fontFamily: 'monospace', fontSize: 12 }} />
            </label>
          </div>
          <div style={{ display: 'flex', gap: 8, marginBottom: 8 }}>
            <div className="form-row" style={{ flex: 1 }}>
              <label>
                Label
                <input value={newLabel} onChange={e => setNewLabel(e.target.value)} placeholder="Name" />
              </label>
            </div>
            <div className="form-row" style={{ width: 100 }}>
              <label>
                Role
                <select value={newRole} onChange={e => setNewRole(e.target.value as 'admin' | 'user')}>
                  <option value="user">User</option>
                  <option value="admin">Admin</option>
                </select>
              </label>
            </div>
          </div>
          <button className="btn btn-primary" onClick={handleAddUser} disabled={!newAddress.trim() || !newLabel.trim()}>Add User</button>
        </div>
      </div>

      {/* Invites */}
      <div className="card">
        <h2>Invite Codes</h2>
        {invites.length === 0 && <p style={{ color: 'var(--white-dim)', fontSize: 13 }}>No active invites.</p>}
        {invites.map(inv => (
          <div key={inv.code} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '8px 0', borderBottom: '1px solid var(--gray-dark)' }}>
            <div>
              <strong style={{ fontFamily: 'monospace', fontSize: 16, letterSpacing: '0.1em' }}>{inv.code}</strong>
              <div style={{ fontSize: 12, color: 'var(--white-dim)', marginTop: 2 }}>
                {inv.usesLeft} uses left · expires {new Date(inv.expiresAt).toLocaleDateString()}
              </div>
            </div>
            <button className="btn btn-secondary" style={{ fontSize: 12, padding: '4px 10px', color: 'var(--red)' }} onClick={() => handleDeleteInvite(inv.code)}>
              Revoke
            </button>
          </div>
        ))}

        <div style={{ marginTop: 16, paddingTop: 16, borderTop: '1px solid var(--gray-dark)' }}>
          <h3 style={{ fontSize: 14, marginBottom: 8 }}>Generate Invite</h3>
          <div style={{ display: 'flex', gap: 8, marginBottom: 8 }}>
            <div className="form-row" style={{ flex: 1 }}>
              <label>
                Max Uses
                <input type="number" min={1} max={100} value={inviteMaxUses} onChange={e => setInviteMaxUses(Number(e.target.value))} />
              </label>
            </div>
            <div className="form-row" style={{ flex: 1 }}>
              <label>
                Expires In (hours)
                <input type="number" min={1} max={720} value={inviteExpiryHours} onChange={e => setInviteExpiryHours(Number(e.target.value))} />
              </label>
            </div>
          </div>
          <button className="btn btn-primary" onClick={handleCreateInvite}>Generate Code</button>
        </div>
      </div>
    </>
  );
}
```

- [ ] **Step 2: Verify it compiles**

Run: `npx tsc -b`

- [ ] **Step 3: Commit**

```bash
git add src/components/UserManager.tsx
git commit -m "feat: UserManager component — user CRUD + invites + visibility"
```

---

### Task 11: Update Settings to embed UserManager

**Files:**
- Modify: `src/components/Settings.tsx`

- [ ] **Step 1: Import and render UserManager for wallet auth mode admins**

Add import:
```typescript
import { UserManager } from './UserManager';
import { getSessionRole } from '../lib/api';
```

In the Settings component body, after the existing state declarations, add:
```typescript
const sessionRole = getSessionRole();
const isWalletAuth = config?.authMode === 'wallet';
const isAdmin = isWalletAuth ? sessionRole === 'admin' : unlocked;
```

Replace `isLocked` usage: for wallet mode, `isLocked` should be `!isAdmin` (no password unlock needed). Adjust the logic:
```typescript
const isLocked = isWalletAuth ? !isAdmin : (needsAdmin && !unlocked);
```

Hide the password unlock bar when in wallet mode (it's not applicable):
```typescript
{isLocked && !isWalletAuth && ( /* existing unlock bar */ )}
```

After the Contracts card and before Reset, add:
```typescript
{isWalletAuth && isAdmin && <UserManager />}
```

- [ ] **Step 2: Verify it compiles**

Run: `npx tsc -b`

- [ ] **Step 3: Commit**

```bash
git add src/components/Settings.tsx
git commit -m "feat: embed UserManager in Settings for wallet auth admins"
```

---

### Task 12: Update InstallWizard for auth mode selection

**Files:**
- Modify: `src/components/InstallWizard.tsx`

- [ ] **Step 1: Add auth mode step**

Add state for auth mode and wallet:
```typescript
const [authMode, setAuthMode] = useState<'password' | 'wallet'>('password');
const [walletAddress, setWalletAddress] = useState('');
const [walletConnecting, setWalletConnecting] = useState(false);
```

Change step type to `1 | 2 | 3`:
```typescript
const [step, setStep] = useState<1 | 2 | 3>(1);
```

Add a third step-dot in the steps indicator.

Insert step 2 (auth mode) between current step 1 (network) and step 2 (storage). Current step 2 becomes step 3.

**Step 2 content** (new, auth mode selection):
```tsx
{step === 2 && (
  <div className="card">
    <h2>Authentication</h2>
    <p>How should this instance control access?</p>
    <div style={{ display: 'flex', flexDirection: 'column', gap: 12, marginBottom: 16 }}>
      {([
        ['password', 'Admin Password', 'Protect settings with a password. Simple setup.'],
        ['wallet', 'OPWallet (ML-DSA)', 'Authenticate with OPWallet signatures. Role-based access for multiple users.'],
      ] as const).map(([value, label, desc]) => (
        <label key={value} style={{
          display: 'flex', alignItems: 'flex-start', gap: 12, padding: 12,
          background: authMode === value ? 'var(--accent-dim)' : 'var(--bg-raised)',
          borderRadius: 'var(--radius)', cursor: 'pointer',
          border: authMode === value ? '1px solid var(--accent)' : '1px solid rgba(237,239,242,0.06)',
        }}>
          <input type="radio" name="authMode" value={value} checked={authMode === value}
            onChange={() => setAuthMode(value)} style={{ marginTop: 4 }} />
          <div>
            <div style={{ fontWeight: 600, fontSize: 14 }}>{label}</div>
            <div style={{ fontSize: 13, color: 'var(--white-dim)' }}>{desc}</div>
          </div>
        </label>
      ))}
    </div>

    {authMode === 'wallet' && !walletAddress && (
      <button className="btn btn-primary btn-full" onClick={async () => {
        const wallet = window.opnet;
        if (!wallet) { setError('OPWallet not detected'); return; }
        setWalletConnecting(true);
        try {
          const accounts = await wallet.requestAccounts();
          if (accounts?.length) setWalletAddress(accounts[0]!);
        } catch { setError('Wallet connection rejected'); }
        setWalletConnecting(false);
      }} disabled={walletConnecting}>
        {walletConnecting ? <span className="spinner" /> : 'Connect OPWallet'}
      </button>
    )}

    {authMode === 'wallet' && walletAddress && (
      <div style={{ padding: 12, background: 'var(--bg-raised)', borderRadius: 'var(--radius)', fontSize: 13 }}>
        <div style={{ color: 'var(--green)', marginBottom: 4 }}>Wallet connected</div>
        <div style={{ fontFamily: 'monospace', fontSize: 11, color: 'var(--white-dim)' }}>{walletAddress}</div>
        <div style={{ fontSize: 12, marginTop: 4 }}>This wallet will be the first admin.</div>
      </div>
    )}

    {error && <div className="warning">{error}</div>}

    <div style={{ display: 'flex', gap: 12, marginTop: 16 }}>
      <button className="btn btn-secondary" onClick={() => setStep(1)}>Back</button>
      <button className="btn btn-primary" style={{ flex: 1 }}
        onClick={() => { setError(''); setStep(3); }}
        disabled={authMode === 'wallet' && !walletAddress}>
        Next
      </button>
    </div>
  </div>
)}
```

Update step 3 (was step 2): only show admin password fields when `authMode === 'password'`. Hide them when `authMode === 'wallet'`.

Update `handleInit` to pass `authMode` and wallet info:
```typescript
await initInstance(
  network,
  storageMode,
  storageMode === 'encrypted-persistent' ? password : undefined,
  authMode === 'password' ? adminPassword : undefined,
  authMode,
  authMode === 'wallet' ? walletAddress : undefined,
  authMode === 'wallet' ? 'Admin' : undefined,
);
```

- [ ] **Step 2: Verify it compiles**

Run: `npx tsc -b`

- [ ] **Step 3: Commit**

```bash
git add src/components/InstallWizard.tsx
git commit -m "feat: auth mode selection in install wizard"
```

---

### Task 13: Update App.tsx for wallet auth gate

**Files:**
- Modify: `src/App.tsx`

- [ ] **Step 1: Add wallet auth gate**

Import `WalletAuth`:
```typescript
import { WalletAuth } from './components/WalletAuth';
```

Update `StatusResponse` usage — check `authMode`:

After `checkStatus` resolves with `status.state === 'ready'`, if `status.authMode === 'wallet'`, check if user has a valid session. If not, show `WalletAuth` gate.

Add a `walletAuth` view:
```typescript
type View = 'loading' | 'wizard' | 'unlock' | 'walletAuth' | 'wallet' | 'dkg' | 'signing' | 'settings';
```

In `checkStatus`, after the `ready` state checks, add wallet auth detection:
```typescript
if (status.authMode === 'wallet') {
  // Check if we have a valid session
  const { getAuthMe } = await import('./lib/api');
  try {
    const me = await getAuthMe();
    if (!me.authenticated) {
      setView('walletAuth');
      return;
    }
  } catch {
    setView('walletAuth');
    return;
  }
}
```

Add the render case:
```typescript
if (view === 'walletAuth') {
  return <WalletAuth onAuthenticated={() => checkStatus()} />;
}
```

- [ ] **Step 2: Verify it compiles**

Run: `npx tsc -b`

- [ ] **Step 3: Commit**

```bash
git add src/App.tsx
git commit -m "feat: wallet auth gate in App.tsx"
```

---

### Task 14: Build, verify, and commit

- [ ] **Step 1: Full backend + frontend build**

Run: `cd backend && npx tsc && cd .. && npx tsc -b && npm run build`

Fix any compilation errors.

- [ ] **Step 2: Docker build test**

Run: `docker build -t permafrost-vault . 2>&1 | tail -10`

- [ ] **Step 3: Final commit and push**

```bash
git add -A
git commit -m "feat: OPWallet ML-DSA authentication with role-based access

- Challenge-response auth using ML-DSA signatures via OPWallet
- Three roles: admin, user, everybody
- Invite codes for user onboarding
- Admin CRUD for users and invites
- Visibility toggle for unauthenticated visitors
- Replaces admin password when wallet auth is enabled
- Backward compatible: password mode unchanged"
git push
```
