# Ötzi — Interface Contracts

An inventory of the system's interfaces and contracts, documented according to
Bertrand Meyer's **Design by Contract** philosophy: every module supplier
publishes what it requires (preconditions), what it guarantees (postconditions),
and what must always hold (invariants).

---

## Table of Contents

1. [ConfigStore](#1-configstore)
2. [Encryption (crypto.ts / share-crypto.ts)](#2-encryption)
3. [Binary Serialization (serialize.ts)](#3-binary-serialization)
4. [DKG Blob Protocol (dkg.ts)](#4-dkg-blob-protocol)
5. [Threshold Signing Protocol (threshold.ts)](#5-threshold-signing-protocol)
6. [ThresholdMLDSASigner Adapter](#6-thresholdmldsasigner-adapter)
7. [RelayClient](#7-relayclient)
8. [REST API — Config Routes](#8-rest-api--config-routes)
9. [REST API — Wallet Routes](#9-rest-api--wallet-routes)
10. [REST API — Transaction Routes](#10-rest-api--transaction-routes)
11. [REST API — Balance Routes](#11-rest-api--balance-routes)
12. [REST API — Hosting Routes](#12-rest-api--hosting-routes)
13. [Frontend API Client (api.ts)](#13-frontend-api-client)
14. [Type System (vault-types.ts)](#14-type-system)

---

## 1. ConfigStore

**Module:** `backend/src/lib/config-store.ts`

Manages the vault configuration lifecycle: initialization, loading, updating,
exporting, and resetting. Acts as the single source of truth for server-side
state.

### Class Invariants

- At most one `VaultConfig` instance exists in memory at a time (`this.config`).
- `this.storageMode` always matches `this.config.storageMode` when config is loaded.
- `encrypted-portable` mode never writes to disk. `persist()` is a no-op for that mode.
- The on-disk file at `CONFIG_PATH` is either valid JSON (persistent mode) or
  an encrypted ciphertext blob (encrypted-persistent mode) — never a hybrid.

### `isInitialized(): boolean`

| Aspect | Contract |
|---|---|
| **Precondition** | None. |
| **Postcondition** | Returns `true` iff `this.config` is non-null OR a file exists at `CONFIG_PATH`. Pure query — no side effects. |

### `init(network, storageMode, password?): void`

| Aspect | Contract |
|---|---|
| **Precondition** | `isInitialized() === false`. If `storageMode === 'encrypted-persistent'`, `password` must be provided. |
| **Postcondition** | `this.config` holds a fresh `defaultConfig(network, storageMode)`. Config is persisted to disk (unless portable). `isInitialized() === true`. |
| **Exception** | Throws `'Already initialized'` if precondition violated. Throws `'Password required...'` if encrypted mode lacks password. |

### `load(password?): VaultConfig`

| Aspect | Contract |
|---|---|
| **Precondition** | Config file exists at `CONFIG_PATH`. If file is encrypted, `password` must be provided and correct. |
| **Postcondition** | `this.config` is populated. Returned config equals `this.config`. `this.storageMode` matches `config.storageMode`. Idempotent — if already loaded, returns cached config without re-reading disk. |
| **Exception** | Throws `'Not initialized'` if no file. Throws `'Password required to unlock'` if encrypted without password. Throws on decryption failure (wrong password / corrupted). |

### `get(): VaultConfig`

| Aspect | Contract |
|---|---|
| **Precondition** | `this.config !== null` (i.e., `init()` or `load()` was called). |
| **Postcondition** | Returns the current in-memory config. Pure query — no side effects. |
| **Exception** | Throws `'Config not loaded'`. |

### `update(patch, password?): VaultConfig`

| Aspect | Contract |
|---|---|
| **Precondition** | `this.config !== null`. If `storageMode === 'encrypted-persistent'`, `password` should be provided for persistence. |
| **Postcondition** | `this.config` is the shallow merge of old config and `patch`. Persisted to disk (unless portable). Returns updated config. |
| **Exception** | Throws `'Config not loaded'`. |

### `importPortable(config): void`

| Aspect | Contract |
|---|---|
| **Precondition** | `config` is a valid `VaultConfig` object. |
| **Postcondition** | `this.config = config`, `this.storageMode = 'encrypted-portable'`. Nothing written to disk. |

### `exportConfig(): string`

| Aspect | Contract |
|---|---|
| **Precondition** | `this.config !== null`. |
| **Postcondition** | Returns `JSON.stringify(this.config)`. Pure query. |
| **Exception** | Throws `'Config not loaded'`. |

### `reset(): void`

| Aspect | Contract |
|---|---|
| **Precondition** | None. |
| **Postcondition** | `this.config === null`, `this.storageMode === null`. Config file deleted from disk if it existed. `isInitialized() === false`. |

---

## 2. Encryption

### `crypto.ts` — AES-256-GCM with PBKDF2

**Module:** `src/lib/crypto.ts`

#### Module Invariants

- `PBKDF2_ITERATIONS = 600_000` (OWASP recommendation).
- Salt is 16 bytes, IV is 12 bytes, both cryptographically random per encryption.
- Wire format: `base64(salt[16] || iv[12] || ciphertext)`.

#### `encrypt(data, password): Promise<string>`

| Aspect | Contract |
|---|---|
| **Precondition** | `data` is a non-null `Uint8Array`. `password` is a non-empty string. Web Crypto API available. |
| **Postcondition** | Returns a base64 string encoding `salt + iv + AES-256-GCM(data)`. A fresh random salt and IV are generated. The same plaintext + password yields a different ciphertext each call. |

#### `decrypt(encoded, password): Promise<Uint8Array>`

| Aspect | Contract |
|---|---|
| **Precondition** | `encoded` is a base64 string produced by `encrypt()`. `password` matches the password used during encryption. |
| **Postcondition** | Returns the original plaintext bytes. `decrypt(encrypt(data, pw), pw) === data`. |
| **Exception** | Throws `DOMException` (Web Crypto) on wrong password or corrupted ciphertext — the AES-GCM authentication tag fails. |

### `share-crypto.ts` — Share File Decryption

**Module:** `src/lib/share-crypto.ts`

#### `decryptShareFile(file, password): Promise<DecryptedShare>`

| Aspect | Contract |
|---|---|
| **Precondition** | `file` is a valid `ShareFile` with `version >= 1`. `file.encrypted` is a base64 blob produced by `encrypt()` with the given `password`. |
| **Postcondition** | Returns a `DecryptedShare` where: `publicKey`, `partyId`, `threshold`, `parties`, `level` are copied from `file`; `shareBytes` is the raw decrypted binary; `keyShare` is a deserialized `ThresholdKeyShare`; `K` and `L` match the security level. |
| **Exception** | Throws on wrong password (AES-GCM auth failure). Throws `'Unknown share version'` if binary format version !== 0x02. |

---

## 3. Binary Serialization

**Module:** `src/lib/serialize.ts`

Converts `ThresholdKeyShare` objects to/from compact binary representation using
23-bit polynomial coefficient packing.

### Module Invariants

- Version byte is always `0x02`.
- Polynomial coefficients are in `[0, Q)` where `Q = 8380417`.
- Each polynomial packs 256 coefficients into exactly 736 bytes (23 bits each).
- `deserializeKeyShare(serializeKeyShare(share, K, L))` yields an equivalent share with the same `K` and `L`.

#### `serializeKeyShare(share, K, L): Uint8Array`

| Aspect | Contract |
|---|---|
| **Precondition** | `share` is a valid `ThresholdKeyShare` with: `share.rho` (32 bytes), `share.key` (32 bytes), `share.tr` (64 bytes). `K` and `L` are positive integers matching the security level. Each `SecretShare` in `share.shares` has exactly `L` s1 polynomials, `K` s2 polynomials, `L` s1Hat polynomials, `K` s2Hat polynomials, each of 256 `Int32` coefficients in `[0, Q)`. |
| **Postcondition** | Returns a `Uint8Array` of exactly `4 + 128 + 2 + numShares * (2 + (2L+2K) * 736)` bytes. First byte is `0x02`. Negative coefficients are normalized to `[0, Q)` via `c + Q`. |

#### `deserializeKeyShare(bytes): { share, K, L }`

| Aspect | Contract |
|---|---|
| **Precondition** | `bytes[0] === 0x02`. Buffer is at least 132 bytes (header + fixed fields). Remaining bytes are consistent with the embedded `numShares`, `K`, and `L` values. |
| **Postcondition** | Returns `{ share, K, L }` where `share` is a reconstructed `ThresholdKeyShare`. All polynomial coefficients are in `[0, 2^23)`. |
| **Exception** | Throws `'Unknown share version'` if `bytes[0] !== 0x02`. |

---

## 4. DKG Blob Protocol

**Module:** `src/lib/dkg.ts`

Encodes/decodes DKG ceremony messages as base64 JSON envelopes for exchange
between parties (copy-paste or relay).

### Envelope Invariants

- Every blob is `base64(JSON({ v: 2, type, from, to, sid, data }))`.
- `sid` is the first 16 hex characters of the 32-byte session ID — enough to
  detect session mismatch without leaking the full ID.
- `to === -1` means broadcast; `to >= 0` means private to that party.
- `data` is hex-encoded binary payload.

### Blob Type Contracts

| Function | Type | Preconditions | Postconditions |
|---|---|---|---|
| `encodeSessionConfig(t, n, level, sessionId)` | `session` | `t <= n`, `level` in `{44,65,87,128,192,256}`, `sessionId` is 32 bytes | Returns blob containing JSON `{t, n, level, sid}`. `from=0, to=-1`. |
| `decodeSessionConfig(blob)` | `session` | Valid base64 blob with `type === 'session'` | Returns `SessionConfig` or `null` on invalid input. |
| `encodePhase1Broadcast(broadcast, sid)` | `p1` | `broadcast.rhoCommitment` is 32 bytes. Each bitmask commitment is 32 bytes. | Binary layout: `1B partyId + 32B rho + N*(2B bitmask + 32B commitment)`. |
| `encodePhase2Broadcast(broadcast, sid)` | `p2pub` | `broadcast.rho` is 32 bytes. | Binary layout: `1B partyId + 32B rho`. |
| `encodePhase2Private(priv, target, sid)` | `p2priv` | Each bitmask reveal is 32 bytes. | `to = targetPartyId` (private message). |
| `encodePhase3Private(priv, target, sid)` | `p3priv` | Each polynomial has 256 `Int32` coefficients. | Appends SHA-256 checksum (32 bytes) for integrity. `to = targetPartyId`. |
| `decodePhase3Private(blob)` | `p3priv` | Blob is valid and `>= 32` bytes of data. | Verifies SHA-256 checksum. Validates all coefficients in `[0, Q)` where `Q = 8380417`. Returns `null` on integrity failure or out-of-range coefficients. |
| `encodePhase4Broadcast(broadcast, sid)` | `p4` | `broadcast.aggregate` is an array of `Int32Array[256]`. | Binary layout: `1B partyId + 1B numPolys + polys`. `to = -1`. |

### `identifyBlob(blob): BlobInfo | null`

| Aspect | Contract |
|---|---|
| **Precondition** | None (accepts arbitrary strings). |
| **Postcondition** | Returns `{ type, from, to, sid }` if blob is a valid v2 envelope, `null` otherwise. Pure query. |

### `getKL(level): { K, L }`

| Aspect | Contract |
|---|---|
| **Precondition** | `level` is one of `{44, 65, 87, 128, 192, 256}`. |
| **Postcondition** | Returns the ML-DSA parameter pair: `44/128 -> {4,4}`, `65/192 -> {6,5}`, `87/256 -> {8,7}`. |
| **Exception** | Throws `'Unknown security level'` for any other value. |

---

## 5. Threshold Signing Protocol

**Module:** `src/lib/threshold.ts`

Implements a 3-round threshold ML-DSA signing protocol with blob-based
message exchange.

### Session Invariants

- `session.msgPrefix` is the first 16 hex chars of `session.message` — used to
  validate that all parties are signing the same message.
- `session.activePartyIds` contains exactly `T` party IDs (the threshold quorum).
- Party ordering is canonically sorted (`[...ids].sort((a,b) => a-b)`) in
  rounds 2, 3, and combine — all parties must agree on ordering.
- Each collection map (`collectedRound*`) is keyed by `partyId` and rejects
  duplicates.

### `createSession(message, share, activePartyIds): SigningSession`

| Aspect | Contract |
|---|---|
| **Precondition** | `message` is non-empty `Uint8Array`. `share` is a valid `DecryptedShare`. `activePartyIds.length === share.threshold`. `share.partyId` is in `activePartyIds`. |
| **Postcondition** | Returns a fresh `SigningSession` with all collection maps empty, all round states null, `signature` null. `instance` is a `ThresholdMLDSA` created with the share's security level, threshold, and party count. |

### `round1(session): string`

| Aspect | Contract |
|---|---|
| **Precondition** | Session was just created (or reset for retry). `session.round1State === null`. |
| **Postcondition** | `session.round1State` is populated. `session.myRound1Hash` holds the commitment hash. Own hash is added to `collectedRound1Hashes`. Returns a base64 blob with `round=1`. |

### `round2(session): string`

| Aspect | Contract |
|---|---|
| **Precondition** | `session.round1State !== null` (round 1 completed). `collectedRound1Hashes` contains entries for all `activePartyIds` (T hashes collected, including own). |
| **Postcondition** | `session.round2State` is populated. `session.myRound2Commitment` holds the commitment. Own commitment is added to `collectedRound2Commitments`. Returns a base64 blob with `round=2`. Hashes were passed to the library in canonically sorted party ID order. |
| **Exception** | Throws `'round1 not completed'`. Throws `'Missing round1 hash from party X'` if any active party's hash is absent. |

### `round3(session): string`

| Aspect | Contract |
|---|---|
| **Precondition** | `session.round1State !== null` and `session.round2State !== null`. `collectedRound2Commitments` contains entries for all `activePartyIds`. |
| **Postcondition** | `session.myRound3Response` holds the partial response. Own response is added to `collectedRound3Responses`. Returns a base64 blob with `round=3`. Commitments were passed in canonically sorted order. |
| **Exception** | Throws if round1 or round2 not completed. Throws if missing commitments. |

### `combine(session): Uint8Array | null`

| Aspect | Contract |
|---|---|
| **Precondition** | All 3 rounds completed. `collectedRound2Commitments` and `collectedRound3Responses` contain entries for all `activePartyIds`. |
| **Postcondition** | Returns a FIPS 204 ML-DSA signature on success, or `null` if this attempt failed (probabilistic — retry from round 1). On success, `session.signature` is set. Commitments and responses are passed in canonically sorted order. |
| **Exception** | Throws if missing commitments or responses for any active party. |

### `addBlob(session, blob, expectedRound?): { ok, error? }`

| Aspect | Contract |
|---|---|
| **Precondition** | `blob` is a string (possibly invalid). |
| **Postcondition** | If valid: adds the blob's data to the appropriate collection map and returns `{ ok: true }`. Returns `{ ok: false, error }` (never throws) on any of: invalid format, wrong round, wrong message prefix, self-blob, party not in active set, duplicate from same party. |

### `signWithRetry(session, onRound, waitForRound, maxAttempts): Promise<Uint8Array>`

| Aspect | Contract |
|---|---|
| **Precondition** | `session` is a valid session. `onRound` broadcasts the blob. `waitForRound` resolves when all blobs for that round are collected. `maxAttempts >= 1`. |
| **Postcondition** | Returns a valid ML-DSA signature. Each failed `combine()` resets all round state (destroys WASM state, clears collections) and retries from round 1. |
| **Exception** | Throws `'Signing failed after N attempts'` if all attempts fail. |

### `destroySession(session): void`

| Aspect | Contract |
|---|---|
| **Precondition** | None. |
| **Postcondition** | `round1State` and `round2State` are destroyed (WASM cleanup) and set to null. Safe to call multiple times. |

---

## 6. ThresholdMLDSASigner Adapter

**Module:** `backend/src/lib/threshold-signer.ts`

Adapts a pre-computed threshold ML-DSA signature to the `QuantumBIP32Interface`
expected by the OPNet SDK's `sendTransaction()`.

### Class Invariants

- `privateKey` is always `undefined` (no private key material — signature is pre-computed).
- `isNeutered()` always returns `true`.
- `sign()` returns the same pre-computed signature regardless of input message.
- Key derivation operations (`derive`, `deriveHardened`, `derivePath`) are unsupported and throw.

### `constructor(precomputedSignature, publicKey)`

| Aspect | Contract |
|---|---|
| **Precondition** | `precomputedSignature` is a valid ML-DSA signature `Uint8Array`. `publicKey` is the combined DKG public key `Uint8Array`. |
| **Postcondition** | Object is ready for use as `mldsaSigner` in `sendTransaction()`. |

### `sign(_message): Uint8Array`

| Aspect | Contract |
|---|---|
| **Precondition** | A valid pre-computed signature was provided at construction. |
| **Postcondition** | Returns `this.precomputedSignature` unchanged. The `_message` parameter is ignored — the signature was already computed by the threshold protocol against the correct message. |
| **Caveat** | The caller (OPNet SDK) is trusted to pass the same message that was used during the threshold signing ceremony. Misuse (different message) would produce an invalid transaction that the network rejects. |

### `verify(_hash, _signature): boolean`

| Aspect | Contract |
|---|---|
| **Precondition** | None. |
| **Postcondition** | Always returns `true`. Not used during `sendTransaction()` flow. |

---

## 7. RelayClient

**Module:** `src/lib/relay.ts`

E2E encrypted WebSocket relay for multi-party ceremony coordination.

### Class Invariants

- `partyId === -1` until `create()` or `join()` resolves.
- `isReady === false` until the `ready` wire message has been processed and all
  AES keys derived.
- `peerKeys` contains exactly `N-1` AES keys (one per peer) after `isReady`.
- `sessionCode` is non-empty after `create()` or `join()`.
- `closed === true` after `close()` — reconnection is disabled.
- Relay messages arriving before `isReady` are queued behind `readyGate` and
  processed only after AES keys are available.

### `create(parties, threshold): Promise<{ session, url }>`

| Aspect | Contract |
|---|---|
| **Precondition** | `parties >= 2`, `threshold >= 1 && threshold <= parties`. No prior `create()` or `join()` on this instance. |
| **Postcondition** | ECDH keypair generated. WebSocket connected. Server confirmed session creation. `partyId` assigned (always 0 for creator). `sessionCode` set. `token` stored in sessionStorage. Resolves with session code and shareable URL. |
| **Exception** | Rejects on WebSocket error or server error message. |

### `join(session): Promise<void>`

| Aspect | Contract |
|---|---|
| **Precondition** | `session` is a valid 6-character session code. No prior `create()` or `join()`. |
| **Postcondition** | ECDH keypair generated. `partyId` assigned by server. `token` stored. Resolves when server confirms join. Does NOT wait for `ready` — that comes when all parties have joined. |
| **Exception** | Rejects on invalid session, full session, or WebSocket error. |

### `send(to, payload): Promise<void>`

| Aspect | Contract |
|---|---|
| **Precondition** | `isReady === true`. `to` is a valid peer party ID with a derived AES key. `payload` is a `Uint8Array`. |
| **Postcondition** | `payload` is encrypted with the peer's AES key and sent over WebSocket as a `relay` wire message. |
| **Exception** | Throws `'No AES key for party X'` if peer key not found. |

### `broadcast(payload): Promise<void>`

| Aspect | Contract |
|---|---|
| **Precondition** | `isReady === true`. At least one peer key exists. |
| **Postcondition** | `payload` is individually encrypted and sent to each peer (N-1 messages). All sends are concurrent (`Promise.all`). |

### `close(): void`

| Aspect | Contract |
|---|---|
| **Precondition** | None. |
| **Postcondition** | `closed = true`. WebSocket closed with code 1000. `keypair` cleared. `peerKeys` cleared. Session token removed from sessionStorage. No reconnection will occur. Idempotent. |

### Reconnection Contract

| Aspect | Contract |
|---|---|
| **Precondition** | `closed === false`. `keypair` still exists in memory (no page reload). Reconnection token available. `reconnectAttempts < maxReconnectAttempts (10)`. |
| **Postcondition** | New WebSocket opened. `reconnect` wire message sent with saved token. On success, `reconnectAttempts` reset to 0. |
| **Failure** | After 10 failed attempts, emits `'error'` with `'Max reconnection attempts reached'`. If keypair is lost (page reload), emits `'Encryption keys lost'` immediately. |

---

## 8. REST API — Config Routes

**Module:** `backend/src/routes/config.ts`

### `GET /api/status`

| Aspect | Contract |
|---|---|
| **Precondition** | None. |
| **Postcondition** | Returns `{ state: 'fresh' }` if not initialized, `{ state: 'locked' }` if encrypted but not unlocked, `{ state: 'ready', setupState, storageMode, network, authMode }` if loaded. Never fails. |

### `POST /api/init`

| Aspect | Contract |
|---|---|
| **Precondition** | `body.network` in `{'testnet','mainnet'}`. `body.storageMode` in `{'persistent','encrypted-persistent','encrypted-portable'}`. If `storageMode === 'encrypted-persistent'`, `body.password` required. Instance must not be initialized (`store.isInitialized() === false`). |
| **Postcondition** | Instance initialized with default config. Returns `{ ok: true }`. |
| **Error** | 400 if missing fields or missing password. 409 if already initialized. |

### `POST /api/unlock`

| Aspect | Contract |
|---|---|
| **Precondition** | `body.password` is non-empty. Instance is initialized but locked (encrypted-persistent mode). |
| **Postcondition** | Config loaded and decrypted. Returns `{ ok: true, config }` where config is sanitized (no mnemonic). |
| **Error** | 400 if no password. 401 on wrong password or corrupted config. |

### `GET /api/config`

| Aspect | Contract |
|---|---|
| **Precondition** | Config is loaded (not fresh, not locked). |
| **Postcondition** | Returns sanitized config (wallet mnemonic stripped). |
| **Error** | 503 if config not loaded. |

### `POST /api/config/contracts`

| Aspect | Contract |
|---|---|
| **Precondition** | Config loaded. `body.contracts` is an array. |
| **Postcondition** | Config updated with new contracts array. Persisted. Returns `{ ok: true }`. |
| **Error** | 400 if `contracts` is not an array. |

### `POST /api/config/export`

| Aspect | Contract |
|---|---|
| **Precondition** | Config loaded. |
| **Postcondition** | Returns `{ config: '<json string>' }`. |

### `POST /api/config/import`

| Aspect | Contract |
|---|---|
| **Precondition** | `body.config` is a `VaultConfig` object or JSON string. |
| **Postcondition** | Config imported in portable mode (memory-only). Returns sanitized config. |
| **Error** | 400 if config missing or invalid JSON. |

### `POST /api/dkg/save`

| Aspect | Contract |
|---|---|
| **Precondition** | Config loaded. `body` contains `threshold`, `parties`, `level`, `combinedPubKey`, `shareData`. Optional FROST fields: `frostAggregateKey` (hex), `frostUntweakedAggregateKey` (hex), `frostLegacySig` (128-char hex). |
| **Postcondition** | `config.permafrost` set with all provided fields. `config.setupState.dkgComplete = true`. If FROST keys present: `frostP2tr` derived from untweaked aggregate key. If `config.wallet` is absent: a throwaway BTC keypair is auto-generated for SDK protocol-level signatures. Persisted. |

### `POST /api/reset`

| Aspect | Contract |
|---|---|
| **Precondition** | `body.confirm === 'RESET'` (exact string). |
| **Postcondition** | All data wiped. Config file deleted. `store` returns to uninitialized state. |
| **Error** | 400 if confirmation string is wrong. |

---

## 9. REST API — Wallet Routes

**Module:** `backend/src/routes/wallet.ts`

The wallet is auto-generated during DKG save (see `POST /api/dkg/save`). There is no manual wallet generation step.

### `GET /api/wallet/balance`

| Aspect | Contract |
|---|---|
| **Precondition** | Config loaded. |
| **Postcondition** | If no wallet configured: returns `{ balance: 0, configured: false }`. If wallet exists: queries OPNet provider for BTC balance at `frostP2tr` (preferred) or `wallet.p2tr` address. Returns `{ balance: '<satoshis>', configured: true }`. |

---

## 10. REST API — Transaction Routes

**Module:** `backend/src/routes/tx.ts`

### Module Invariant — Double-Broadcast Prevention

- `broadcastResults: Map<string, Result>` is an in-memory lock keyed on
  `messageHash`.
- Once a broadcast succeeds, the result is cached permanently (within process lifetime).
- Once locked (set to `{}`), concurrent requests for the same hash return early.
- On broadcast error, the lock is cleared to allow retry.

### `GET /api/tx/broadcast-status/:messageHash`

| Aspect | Contract |
|---|---|
| **Precondition** | `messageHash` is a hex string. |
| **Postcondition** | Returns `{ broadcast: true, transactionId?, estimatedFees?, error? }` if hash is in the map, `{ broadcast: false }` otherwise. Pure query. |

### `POST /api/tx/encode`

| Aspect | Contract |
|---|---|
| **Precondition** | `body.method` is a string (method name). `body.params` is a `string[]`. `body.paramTypes` is an array of `'address' | 'u256' | 'bytes'` matching params length. |
| **Postcondition** | Returns `{ calldata, messageHash }` where `calldata` is hex-encoded binary (4-byte SHA-256 selector + encoded params) and `messageHash` is `SHA-256(calldata)` in hex. |
| **Encoding** | `address` → raw 32-byte hex. `u256` → `BinaryWriter.writeU256(BigInt(value))`. `bytes` → raw hex bytes. |

### `POST /api/tx/simulate`

| Aspect | Contract |
|---|---|
| **Precondition** | Config loaded. `body.contract` is a valid OPNet contract address. `body.method` exists on the contract. `body.params` matches the method signature. |
| **Postcondition** | Returns `{ success: true, estimatedGas?, events? }` on successful simulation, or `{ success: false, revert }` if the contract call reverts. Params are converted: `address` → `Address.wrap(Buffer)`, `u256` → `BigInt`. |
| **Error** | 400 if method not found on contract. 500 on provider/simulation failure. |

### `POST /api/tx/sighash`

| Aspect | Contract |
|---|---|
| **Precondition** | Config loaded. `config.permafrost` exists with FROST keys (`frostAggregateKey`, `frostUntweakedAggregateKey`). `body.signature` is a hex-encoded ML-DSA signature. `body.contract`, `body.method`, `body.params` define the call. |
| **Postcondition** | Builds a template OPNet transaction with a dummy signer that captures all input sighashes. Template transactions cached server-side keyed by a random `challengeToken`. Returns `{ sighashes: [{index, hash, type}], challengeToken }`. Each sighash has `type: 'script-path'` or `'key-path'` for Taproot signing. |
| **Error** | 400 if no DKG or missing FROST keys. 500 on transaction build failure. |

### `POST /api/tx/broadcast`

| Aspect | Contract |
|---|---|
| **Precondition** | Config loaded. `config.wallet` exists (mnemonic available). `config.permafrost` exists (DKG completed). `body.signature` is a hex-encoded ML-DSA signature. `body.contract`, `body.method`, `body.params` define the call. If `body.messageHash` provided, must not already be successfully broadcast. |
| **Postcondition (FROST path)** | If `body.frostSignatures` and `body.challengeToken` present: retrieves cached template transactions, injects FROST Schnorr signatures into witness data (script-path → witness[2], key-path → witness[0]). Injects FROST legacy signature for key-link if configured. Broadcasts final signed transaction(s). Returns `{ success: true, transactionId, estimatedFees }`. |
| **Postcondition (legacy path)** | If no `frostSignatures`: builds transaction with `ThresholdMLDSASigner` adapter, signs with `wallet.keypair`, and broadcasts. Returns `{ success: true, transactionId, estimatedFees }`. |
| **Double-broadcast** | If `messageHash` was already broadcast successfully, returns cached result with `alreadyBroadcast: true`. Concurrent requests are blocked by immediate lock-set. |
| **Error** | 400 if no wallet or no DKG. 400 if simulation reverts. 500 on broadcast failure (lock cleared for retry). |

---

## 11. REST API — Balance Routes

**Module:** `backend/src/routes/balances.ts`

### `GET /api/balances`

| Aspect | Contract |
|---|---|
| **Precondition** | Config loaded. |
| **Postcondition** | If `config.permafrost` and `config.wallet` both exist: derives the OPNet vault address from `combinedPubKey + tweakedPubKey`, then queries each configured contract for `name`, `symbol`, `decimals`, `balanceOf(vaultAddr)`. Returns `{ balances: [...] }`. Non-OP-20 contracts silently skipped. If either is missing: returns `{ balances: [] }`. |

---

## 12. REST API — Hosting Routes

**Module:** `backend/src/routes/hosting.ts`

### `GET /api/hosting`

| Aspect | Contract |
|---|---|
| **Precondition** | Config loaded. |
| **Postcondition** | Returns `{ hosting }` — either the current `HostingConfig` or `null`. |

### `POST /api/hosting`

| Aspect | Contract |
|---|---|
| **Precondition** | Config loaded. `body.domain` is a string (may be empty). `body.httpsEnabled` is a boolean. |
| **Postcondition** | Hosting config saved. Caddyfile written to `CADDYFILE_PATH`. Caddy reloaded (or started if not running). If HTTPS enabled and domain provided: Caddyfile uses bare domain (Caddy auto-obtains Let's Encrypt cert). If domain without HTTPS: `http://domain` block. If no domain: `:80` catch-all. Returns `{ ok: true, config }`, possibly with `warning` if Caddy not installed. |

### `DELETE /api/hosting`

| Aspect | Contract |
|---|---|
| **Precondition** | Config loaded. |
| **Postcondition** | Hosting config removed from vault config. Default Caddyfile (`:80` proxy) written. Caddy reloaded. Returns `{ ok: true }`. |

---

## 13. Frontend API Client

**Module:** `src/lib/api.ts`

Thin wrapper around `fetch()` for all `/api/*` endpoints.

### Module Invariants

- All requests include `Content-Type: application/json`.
- All responses are parsed as JSON.
- Non-2xx responses throw `Error` with the server's `error` field or `HTTP <status>`.

### General Contract

For every API function:

| Aspect | Contract |
|---|---|
| **Precondition** | Backend server is reachable at the same origin. Arguments match the endpoint's expected types. |
| **Postcondition** | Resolves with the typed response body on success. |
| **Exception** | Throws `Error` on HTTP error (non-2xx) with the server's error message. Throws on network failure. |

---

## 14. Type System

**Module:** `src/lib/vault-types.ts` (frontend) / `backend/src/lib/types.ts` (backend)

### Type Invariants

| Type | Invariants |
|---|---|
| `NetworkName` | Always `'testnet'` or `'mainnet'`. |
| `StorageMode` | Always one of `'persistent'`, `'encrypted-persistent'`, `'encrypted-portable'`. |
| `SetupState` | Two booleans: `wizardComplete` and `dkgComplete`. `dkgComplete` implies a DKG ceremony has been saved and a wallet has been auto-generated. |
| `WalletConfig` (backend) | Contains `mnemonic` (BIP39). Frontend receives `WalletPublic` (no mnemonic) via `sanitizeConfig()`. |
| `PermafrostConfig` | `threshold <= parties`. `level` in `{44,65,87,128,192,256}`. `combinedPubKey` is hex-encoded ML-DSA combined public key. `shareData` is the serialized share for this instance. |
| `ContractConfig` | `address` is a valid OPNet contract address. `abi` is an ABI array. `methods` lists callable method names. |
| `HostingConfig` | `httpsStatus` is only set when `httpsEnabled === true`. `httpsError` is only set when `httpsStatus === 'error'`. |
| `VaultConfig` | `version` is always `1`. `contracts` is always an array (possibly empty). `wallet` is auto-generated at DKG save (not user-facing). `permafrost` is present after DKG ceremony. |

### `sanitizeConfig(config): SanitizedConfig`

| Aspect | Contract |
|---|---|
| **Precondition** | `config` is a valid `VaultConfig`. |
| **Postcondition** | Returns a copy with `wallet.mnemonic` stripped. All other fields preserved. If `wallet` is absent, returned as-is. Never mutates the input. |
| **Security invariant** | The mnemonic NEVER leaves the backend. The wallet is auto-generated internally and its mnemonic is never exposed to the frontend. |

### `defaultConfig(network, storageMode): VaultConfig`

| Aspect | Contract |
|---|---|
| **Precondition** | Valid `network` and `storageMode`. |
| **Postcondition** | Returns a `VaultConfig` with `version: 1`, `wizardComplete: true`, all other setup flags `false`, empty `contracts` array, no `wallet`, no `permafrost`, no `hosting`. |

---

## Cross-Cutting Contracts

### Security Invariants (System-Wide)

1. **Mnemonic confinement:** The BIP39 mnemonic is stored only in
   `config.wallet.mnemonic` on the backend. It is auto-generated during DKG
   save and never exposed to the frontend. `sanitizeConfig()` strips it from
   all responses. Wallet objects are `zeroize()`d after use.

2. **Share encryption:** Key shares are always encrypted at rest with
   AES-256-GCM (PBKDF2 600k iterations). The password never leaves the user's
   browser.

3. **Relay E2E encryption:** All relay messages are encrypted with per-peer
   AES keys derived from ECDH key agreement. The relay server never sees
   plaintext ceremony data.

4. **Phase 3 integrity:** DKG phase 3 blobs include a SHA-256 checksum and
   polynomial coefficient range validation (`[0, Q)`). Corrupted blobs are
   rejected at decode time, not during ceremony computation.

5. **Broadcast idempotency:** Transaction broadcast is locked server-side on
   `messageHash`. Only one party can successfully broadcast; others receive the
   cached result. Lock is cleared on error to allow retry.

6. **Canonical ordering:** Threshold signing rounds 2, 3, and combine always
   sort party IDs ascending before passing data to the cryptographic library.
   This ensures all parties compute identical inputs regardless of collection
   order.

### State Machine (Vault Lifecycle)

```
fresh ──init()──> [persistent | encrypted-persistent | encrypted-portable]
                         │                  │                    │
                    (auto-load)        unlock(pw)          importPortable()
                         │                  │                    │
                         └────────> ready <──┘────────<──────────┘
                                     │
                          ┌──────────┼──────────┐
                          │          │          │
                     walletGen   dkgSave   contracts
                          │          │          │
                          └──> operational <────┘
                                     │
                                  reset()
                                     │
                                   fresh
```

### State Machine (Signing Ceremony)

```
idle ──createSession()──> round1 ──round1()──> collecting_r1
     collecting_r1 ──(T blobs)──> round2 ──round2()──> collecting_r2
     collecting_r2 ──(T blobs)──> round3 ──round3()──> collecting_r3
     collecting_r3 ──(T blobs)──> combine()
                                    │
                           ┌────────┴────────┐
                           │                 │
                       sig (success)    null (retry)
                           │                 │
                        complete     reset & back to round1
                                     (up to maxAttempts)
```

### State Machine (DKG Ceremony)

```
join ──(config exchanged)──> commit ──phase1()──> reveal ──phase2()──>
     masks ──phase3()──> aggregate ──phase4()──> complete
```

Each phase gate requires all `N` parties' blobs before advancing. Session ID
prefix is validated on every incoming blob to prevent cross-session confusion.
