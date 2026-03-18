# OPWallet Authentication Design

**Date:** 2026-03-18
**Status:** Approved

## Summary

Add optional OPWallet-based authentication with ML-DSA challenge-response
signing, three-tier role system (admin/user/everybody), invite codes for user
onboarding, and role-based visibility controls. When enabled, replaces the
admin password entirely.

## Identity Model

**CRITICAL — avoid pubkey confusion:**

| Field | What it is | Used for |
|-------|-----------|----------|
| `mldsaPubKey` | Raw ML-DSA public key (1312/1952/2592 bytes) | Signature verification during auth challenge |
| `walletAddress` | `0x + hex(SHA256(mldsaPubKey))` | User identity, stored in users.json, role lookup |
| `publicKey` / `tweakedPubKey` / `p2tr` | Bitcoin key | Wallet/transaction functionality ONLY — never used for auth |

The auth system exclusively uses `mldsaPubKey` and `walletAddress`. Bitcoin
keys are irrelevant to authentication.

## Auth Flow

Challenge-response adapted from libpam-web3 OPNet plugin:

1. Frontend: `GET /api/auth/challenge` — backend generates
   `{ challenge: randomHex(32), expiresAt }`, stores in memory
2. User connects OPWallet via `window.opnet` API (direct browser API,
   no `@btc-vision/walletconnect` package — avoids React 19 dependency)
3. Frontend constructs message: `"PERMAFROST auth {challenge}"`
4. Frontend SHA256-hashes the message, hex-encodes the hash
5. Calls `window.opnet.web3.signMLDSAMessage(messageHex)`
   (wallet internally SHA256-hashes again — double-hash convention)
6. Frontend: `POST /api/auth/verify` with
   `{ challenge, signature, publicKey }` (base64-encoded sig and pubkey)
7. Backend reconstructs double-hash:
   `signedData = SHA256(hex(SHA256("PERMAFROST auth {challenge}")))`
8. Backend determines ML-DSA level from pubkey size, verifies signature
   using `ml_dsa{44,65,87}.verify()` from vendor post-quantum
9. Backend derives `walletAddress = "0x" + hex(SHA256(pubKeyBytes))`
10. Backend looks up address in user DB → determines role
11. If not found: returns `{ authenticated: false, needsInvite: true }`
12. If found: creates session token, returns `{ token, role, address }`

**Anti-replay:** Challenges are one-use, stored in memory Map, expire after
60 seconds. Consumed on verification attempt (pass or fail).

**Session tokens:** Random 32-byte hex, expire after 1 hour, stored in
memory Map (same mechanism as current admin tokens).

## User Database

**File:** `DATA_DIR/users.json`

```json
{
  "users": [
    { "address": "0xabc...", "role": "admin", "label": "Alice" },
    { "address": "0xdef...", "role": "user", "label": "Bob" }
  ],
  "invites": [
    { "code": "X7K2M9", "role": "user", "usesLeft": 3, "expiresAt": 1773500000000 }
  ],
  "settings": {
    "everybodyCanRead": true
  }
}
```

### Three Roles

| Role | Dashboard | Settings (read) | Signing/Broadcast | Settings (write) | User mgmt |
|------|-----------|----------------|-------------------|------------------|-----------|
| **admin** | Yes | Yes | Yes | Yes | Yes |
| **user** | Yes | Yes | Yes | No | No |
| **everybody** | Configurable | Configurable | No | No | No |

- `everybodyCanRead: true` — unauthenticated visitors see dashboard, balances,
  settings info (read-only)
- `everybodyCanRead: false` — unauthenticated visitors see only a blank page
  with "Connect OPWallet" button

### Invite Codes

Admin generates invite codes from Settings specifying:
- Role to assign (always `user` — admin must be promoted manually)
- Max uses (e.g., 3)
- Expiry timestamp

When a wallet connects and isn't in the DB, frontend prompts for an invite
code. Valid code → user auto-added with the invite's role, uses decremented.
Expired or exhausted invites are rejected.

### First Admin

During setup wizard with wallet auth mode: the first person to connect their
OPWallet becomes admin automatically. No invite code needed. Subsequent users
require either manual addition or an invite code.

## Backend Changes

### New file: `backend/src/lib/users.ts`

`UserStore` class — loads/saves `users.json`:

```
getUser(address): User | null
addUser(address, role, label): void
removeUser(address): void
updateRole(address, role): void
listUsers(): User[]
createInvite(role, maxUses, expiresAt): Invite
redeemInvite(code, address, label): User | null
listInvites(): Invite[]
removeInvite(code): void
```

### New file: `backend/src/routes/auth.ts`

| Method | Path | Auth | Purpose |
|--------|------|------|---------|
| GET | `/api/auth/challenge` | none | Generate one-use challenge |
| POST | `/api/auth/verify` | none | Verify ML-DSA sig, return token + role |
| POST | `/api/auth/redeem` | none | Submit invite code + sig to register |
| GET | `/api/auth/me` | token | Return current session role + address |

### New routes in existing routers (admin-only)

| Method | Path | Purpose |
|--------|------|---------|
| GET | `/api/users` | List all users |
| POST | `/api/users` | Add user (address, role, label) |
| DELETE | `/api/users/:address` | Remove user |
| PATCH | `/api/users/:address` | Update role |
| GET | `/api/invites` | List active invites |
| POST | `/api/invites` | Create invite (role, maxUses, expiry) |
| DELETE | `/api/invites/:code` | Revoke invite |

### Middleware update

`createRequireAdmin(store)` → `createAuthMiddleware(store, userStore)` returning:

- `requireAdmin` — token must map to admin role
- `requireUser` — token must map to admin OR user role
- `requireRead` — blocks everybody when `everybodyCanRead === false`

When wallet auth is disabled (authMode === 'password'), falls back to
current admin password behavior unchanged.

### Endpoint protection by role

| Endpoint | Required role |
|----------|--------------|
| `GET /api/status` | none |
| `GET /api/config` | requireRead |
| `GET /api/balances` | requireRead |
| `GET /api/wallet/balance` | requireRead |
| `GET /api/hosting` | requireRead |
| `GET /api/tx/broadcast-status` | requireRead |
| `POST /api/tx/encode` | requireUser |
| `POST /api/tx/simulate` | requireUser |
| `POST /api/tx/broadcast` | requireUser |
| `POST /api/dkg/save` | requireAdmin |
| `POST /api/config/contracts` | requireAdmin |
| `POST /api/config/import` | requireAdmin |
| `POST /api/hosting` | requireAdmin |
| `DELETE /api/hosting` | requireAdmin |
| `POST /api/wallet/generate` | requireAdmin |
| `POST /api/wallet/skip` | requireAdmin |
| `POST /api/reset` | requireAdmin |
| `GET/POST/DELETE /api/users` | requireAdmin |
| `GET/POST/DELETE /api/invites` | requireAdmin |

### ML-DSA verification

Backend adds `@btc-vision/post-quantum` as `"file:../vendor/post-quantum"`
in `backend/package.json`. Uses `ml_dsa44.verify()`, `ml_dsa65.verify()`,
`ml_dsa87.verify()` from `@btc-vision/post-quantum/ml-dsa.js`.

ML-DSA level determined by public key byte length:
- 1312 bytes → ML-DSA-44 (sig: 2420 bytes)
- 1952 bytes → ML-DSA-65 (sig: 3309 bytes)
- 2592 bytes → ML-DSA-87 (sig: 4627 bytes)

### VaultConfig change

Add `authMode: 'password' | 'wallet'` field. Defaults to `'password'` for
backward compatibility. Set during `POST /api/init`. Returned in
`GET /api/status` so the frontend knows which auth flow to show.

## Frontend Changes

### New file: `src/components/WalletAuth.tsx`

- Detects `window.opnet` browser extension
- "Connect OPWallet" button
- On connect: fetches challenge → signs → verifies → stores token + role
  in sessionStorage
- If not in user DB: shows invite code input
- Wallet indicator in header when connected (truncated address + disconnect)

### Role-based visibility in `App.tsx`

- Checks `authMode` from `GET /api/status`
- If `wallet`: wraps app in wallet auth gate instead of password flow
- Routes/components check role from sessionStorage:
  - `everybody` + `everybodyCanRead: false` → blank page + connect button
  - `everybody` + `everybodyCanRead: true` → read-only dashboard
  - `user` → full dashboard + signing, Settings read-only
  - `admin` → everything unlocked

### Settings additions (admin only)

- **User Management card:** table of users (address, label, role dropdown,
  remove button), add user form
- **Invite Codes card:** active invites list with uses/expiry, generate
  button with max-uses and expiry inputs, revoke button
- **"Everybody visibility" toggle:** switches `everybodyCanRead`

### Setup wizard changes

New step after network/storage selection: "Authentication Mode"

- **Password** — current flow, admin password fields shown
- **OPWallet** — "Connect your OPWallet to register as admin" button,
  no password fields, wallet connect triggers init + first admin creation

## File Inventory

| File | New/Modified |
|------|-------------|
| `backend/src/lib/users.ts` | New |
| `backend/src/lib/auth.ts` | Modified (middleware refactor) |
| `backend/src/routes/auth.ts` | New |
| `backend/src/routes/config.ts` | Modified (user/invite CRUD routes) |
| `backend/src/routes/wallet.ts` | Modified (requireUser on some routes) |
| `backend/src/routes/tx.ts` | Modified (requireUser on encode/simulate/broadcast) |
| `backend/src/routes/hosting.ts` | Modified (requireRead on GET) |
| `backend/src/routes/balances.ts` | Modified (requireRead) |
| `backend/src/server.ts` | Modified (UserStore init, new routers) |
| `backend/src/lib/types.ts` | Modified (authMode field) |
| `backend/package.json` | Modified (add post-quantum dep) |
| `src/components/WalletAuth.tsx` | New |
| `src/components/Settings.tsx` | Modified (user mgmt, invites, visibility toggle) |
| `src/components/InstallWizard.tsx` | Modified (auth mode step) |
| `src/App.tsx` | Modified (wallet auth gate, role context) |
| `src/lib/api.ts` | Modified (auth endpoints, role in token) |
| `src/lib/vault-types.ts` | Modified (authMode) |

## Out of Scope

- `@btc-vision/walletconnect` React provider (requires React 19; we use
  `window.opnet` API directly)
- UniSat wallet support (no ML-DSA capability)
- Password + wallet dual mode (wallet replaces password when enabled)
- Wallet-based encryption of config (auth mode is orthogonal to storage mode)
