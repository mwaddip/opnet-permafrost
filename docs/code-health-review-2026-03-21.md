# Codebase Health Review — 2026-03-21

## Critical (3)

1. **`POST /api/dkg/save` — no input validation.** `threshold`, `parties`, `level`, `combinedPubKey`, `shareData` stored directly from request body with zero validation.
2. **`POST /api/config/contracts` — only checks `Array.isArray`.** Individual contract entries (name, address, abi, methods) not validated.
3. **`POST /api/manifest` — stores raw untrusted data** with no schema validation.

## Important — Input Validation (5)

4. **Caddyfile injection via hosting `domain`/`path`** — not sanitized before writing to Caddyfile.
5. **Restore endpoint auth bypass** — checks for `Bearer` header presence but never validates the token via `getTokenInfo()`.
6. **`POST /api/tx/broadcast` — signature hex not validated** before `Buffer.from(signature, 'hex')`.
7. **`POST /api/tx/encode` — method/params not validated** before encoding.
8. **`POST /api/tx/read` — no param validation** for reads.

## Important — Code Duplication (7)

9. **`toHex`/`fromHex`** — duplicated in 6 files
10. **`buf()` wrapper** — duplicated in 3 files
11. **`deriveKey` + `decrypt`** — identical in crypto.ts and share-crypto.ts
12. **`unpackPoly` + `deserializeKeyShare`** — full copy in serialize.ts AND share-crypto.ts
13. **Relay URL derivation** — identical in DKGWizard.tsx and SigningPage.tsx
14. **`handlePaste`/`handleRelayBlob` in DKGWizard** — near-identical decode-and-dispatch
15. **`ContractFnMap` type** — defined identically in tx.ts and balances.ts

## Important — Resource & Quality (6)

16. **Memory leak: `tokens`, `challenges`, `broadcastResults` Maps** — no periodic cleanup.
17. **`users.json` corruption silently ignored** — starts fresh DB.
18. **Startup config load silently swallowed** — no warning.
19. **`pendingSessionCode` missing from `useCallback` deps** in App.tsx.
20. **`hosting: undefined as never`** — unsafe cast.
21. **`signWithRetry` exported but never used.**

## Suggestions (19)

- `ShareGate` component exported but unused
- `_relayPartyId` prop accepted but voided
- `Q` constant in dkg.ts unused
- Hardcoded tx params (feeRate: 10, priorityFee: 1000n, maximumAllowedSatToSpend: 100000n)
- Invite code entropy low (6 hex chars = 16.7M)
- No graceful shutdown handlers
- Type duplication between frontend/backend VaultConfig (intentional but undocumented)
- `hex.match(/.{2}/g)!` null-unsafe in raw hex mode
- `uint8ToBase64` duplicated across WalletAuth.tsx and relay-crypto.ts
- Error casting pattern `(e as Error).message` repeated 40+ times
