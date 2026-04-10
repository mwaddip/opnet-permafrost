@~/projects/OVERRIDES.md

# CLAUDE.md — Ötzi

## Project Overview

Post-quantum multisig operations platform for OPNet Bitcoin L1 smart contracts. Self-hosted Docker/Linux/Windows app combining DKG key generation, threshold ML-DSA signing, and declarative project manifests.

## Architecture

```
Frontend (React/Vite)  →  Backend (Express/Node)  →  Relay (Go WebSocket)
     src/                   backend/src/               relay/
```

- **Frontend**: React 18, Vite, TypeScript. No CSS framework — inline styles with CSS variables.
- **Backend**: Express, TypeScript. Serves frontend + API + proxies /ws to relay.
- **Relay**: Go, nhooyr.io/websocket. E2E encrypted message relay for ceremonies.
- **Vendor**: `vendor/post-quantum/` — compiled @btc-vision/post-quantum (JS + .d.ts only, no .ts source).

## Key Principles

- **Derive from runtime state** — never hardcode values that can be derived from window.location, process.env, or contract reads. State never lies; config files get stale.
- **Dark theme default** — terminal aesthetic (black bg, orange accent, monospace).
- **Alpha software** — no backward compatibility needed. Breaking changes acceptable.
- **One instance = one DKG key = one project** — no multi-project support.

## Development

```bash
# Terminal 1: Frontend (Vite dev server)
BACKEND_PORT=9080 npm run dev

# Terminal 2: Backend (auto-reload via tsx watch)
DATA_DIR=/tmp/otzi-dev PORT=9080 RELAY_PORT=9081 npm run dev:backend

# Terminal 3: Relay (Go — may need PATH adjustment)
PATH="/usr/local/go/bin:$PATH" npm run dev:relay -- -addr :9081
```

Ports 8080/8081 are occupied on dev machine. Use 9080/9081.

## Build & Deploy

```bash
docker build -t otzi .                       # Docker
./install.sh --domain vault.example.com      # Linux (with or without sudo)
sudo dpkg -i otzi_*.deb                      # Debian/Ubuntu
```

GitHub Actions builds tarball + zip + .deb on tagged releases (`v*`).

## Important: Identity Model

**CRITICAL — avoid pubkey confusion:**

| Field | What it is | Used for |
|-------|-----------|----------|
| `mldsaPubKey` | Raw ML-DSA public key (1312/1952/2592 bytes) | Auth signature verification |
| `walletAddress` | `0x + hex(SHA256(mldsaPubKey))` | User identity in users.json |
| `publicKey` / `tweakedPubKey` / `p2tr` | Bitcoin key | Wallet/transaction ONLY — never for auth |

## Signing Protocol

Leader-driven state-sync:
- Leader (session initiator) drives round advancement
- Joiners follow leader's STATE messages
- `STATE:<partyId>:<round>:<blobsSent>` broadcast every 500ms + on state change
- Leader broadcasts `COMPLETE:<signatureHex>` on success
- Joiners receive signature, don't call combine() independently
- Only leader sees the Broadcast button

## Manifest System

`.otzi.json` files define contract operations declaratively. Schema at `docs/otzi-manifest-schema.json`.
- ABI shorthands (OP_20) resolved on backend via opnet SDK's OP_20_ABI
- Frontend sends raw ABI to backend (don't resolve on frontend — loses output types)
- Dynamic dropdown params via `options: { count, item }` pattern

## Backend ABI Handling

All ABI normalization happens in `backend/src/routes/tx.ts` via `resolveAbi()`:
- Expands string shorthands ("OP_20" → full SDK ABI)
- Normalizes type casing (Function → function, uint256 → UINT256)
- Used by read, simulate, and broadcast routes

## Nginx Requirement

When behind nginx, `proxy_buffering off` is **required** in the location block. Without it, large WebSocket frames (ML-DSA signing blobs) are silently dropped, causing one-directional relay delivery failures.

## File Conventions

- Backend types at `backend/src/lib/types.ts`, frontend types at `src/lib/vault-types.ts` (intentional duplication — security boundary, frontend never sees mnemonic)
- Shared hex utilities in `src/lib/hex.ts` (toHex, fromHex, uint8ToBase64)
- `data/` directory is gitignored (dev data, session context)
- `docs/superpowers/` is gitignored (internal specs/plans)
- `otzi-claude.md` is untracked (original audit file)

## Encrypted Backups

Full system snapshot: wallet (mnemonic), DKG keys, contracts, hosting, manifest, users, invites, visibility. Same encryption as encrypted-persistent config. Restore works on fresh instances (install wizard) and initialized instances (Settings).

## OPNet Dependencies

- `opnet@1.8.6` — contract interactions, OP_20_ABI
- `@btc-vision/transaction@1.8.2` — Address, BinaryWriter
- `@btc-vision/bitcoin@7.0.0` — network types
- `@btc-vision/post-quantum` (vendor) — ML-DSA signing/verification
- Only ML-DSA-44 (level 44) is used for OPNet

## Git Workflow

- All work on `master` branch
- Tag releases as `vX.Y.Z` to trigger GitHub Actions
- Commit messages: conventional commits (feat/fix/docs)
- Always commit from project root (`cd /home/mwaddip/projects/otzi`)
