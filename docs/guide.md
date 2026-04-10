# Ötzi User Guide

## What is Ötzi?

Ötzi is a self-hosted operations interface for OPNet Bitcoin L1 smart contracts. It combines:

- **Distributed Key Generation (DKG)** — T-of-N parties each generate shares of both a post-quantum ML-DSA signing key and a FROST secp256k1 BTC key, without any single party ever seeing the full secrets
- **Dual Threshold Signing** — ML-DSA (3-round) for contract authorization + FROST (2-round) for Bitcoin transaction signing
- **Transaction Broadcasting** — encode calldata, simulate, sign, and broadcast OPNet contract calls
- **Project Manifests** — any OPNet project can define its operations as a declarative `.otzi.json` file

## BTC Wallet Architecture

Ötzi uses **FROST threshold signing** for the BTC wallet. The vault's BTC address is derived from the FROST aggregate key — no single party holds the private key. All Bitcoin transaction inputs are signed via the 2-round FROST ceremony.

An internal throwaway keypair is auto-generated during DKG completion for SDK protocol-level signatures (OPNet SDK internals). This wallet is not user-facing and its mnemonic never leaves the backend.

**Fund the FROST P2TR address** (shown in Settings) with the amount needed for gas fees. A few thousand satoshis is typically sufficient.

## Setup Flow

### 1. Network

Choose Testnet or Mainnet. This determines which OPNet RPC endpoint the instance connects to.

### 2. Authentication

- **Admin Password** — simple password protection for settings. Good for single-operator setups.
- **OPWallet (ML-DSA)** — wallet-based authentication using post-quantum signatures. Supports multiple users with admin/user roles, invite codes, and session-based access for signing ceremonies.

### 3. Storage Mode

| Mode | Data at Rest | Startup |
|------|-------------|---------|
| **Persistent** | Plaintext JSON on disk | Automatic |
| **Encrypted Persistent** | AES-256-GCM encrypted on disk | Requires password on each restart |
| **Encrypted Portable** | Downloaded to your machine | Upload + password each session |

### 4. DKG Ceremony

All T-of-N parties must participate simultaneously:

1. **Initiator** creates a session (chooses T, N, security level)
2. **Other parties** join by pasting the session code or clicking the join link
3. The ceremony runs 9 steps: ML-DSA phases (Commit → Reveal → Masks → Aggregate), FROST phases (FROST Commit → FROST Shares), Key-Link signing, and finalization
4. Each party downloads their encrypted share file (V3 format with both ML-DSA and FROST key shares)
5. The combined ML-DSA public key and FROST BTC address are saved to the instance
6. An internal wallet is auto-generated for SDK protocol signatures

Blob exchange happens via the built-in encrypted WebSocket relay. All relay messages are E2E encrypted — the relay server only forwards ciphertext.

### 6. Operations

After DKG, the signing page shows available operations. If a project manifest is loaded, its operations appear with live contract state and conditional visibility.

## Signing a Transaction

1. **Build** — select an operation, fill parameters, encode calldata
2. **ML-DSA Sign** — each party loads their share file, enters their password, and participates in the 3-round ML-DSA signing protocol. Produces the contract call signature.
3. **FROST Sign** — the server captures sighashes from a template transaction, then parties run a 2-round FROST ceremony to produce BIP340 Schnorr signatures for each Bitcoin input.
4. **Broadcast** — the leader's server injects FROST signatures into the template transaction and broadcasts. Other parties see the result. Double-broadcast is prevented server-side.

From the user's perspective, steps 2-3 are one continuous flow over the same relay session. The signing protocol auto-retries on ML-DSA norm check failures (up to 50 attempts in relay mode).

For a detailed visual walkthrough, see [Signing Flows](signing-flows.md).

## Project Manifests

Any OPNet project can plug into Ötzi by writing a `.otzi.json` manifest. See the [README](../README.md#project-manifests) and the [JSON Schema](otzi-manifest-schema.json) for the full specification.

### Quick Example

```json
{
  "version": 1,
  "name": "My Token",
  "contracts": {
    "token": { "label": "MyToken", "abi": "OP_20" }
  },
  "operations": [
    {
      "id": "transfer",
      "label": "Transfer",
      "contract": "token",
      "method": "transfer",
      "params": [
        { "name": "to", "type": "address", "label": "Recipient" },
        { "name": "amount", "type": "uint256", "label": "Amount", "scale": 100000000 }
      ]
    }
  ]
}
```

Import in **Settings > Project Manifest**, configure the contract address, and you're signing and broadcasting through threshold ML-DSA.

### Manifest Features

- **Contracts** — define any number with custom ABIs or built-in shorthands (`OP_20`, `OP_721`)
- **State reads** — poll contract values on a timer, with optional parameters (e.g., `balanceOf(reserveAddress)`)
- **Status panel** — dashboard of live values with format hints and value-to-label mapping
- **Operations** — parameter auto-fill from contract addresses/settings/reads, scale multipliers, confirmation prompts
- **Conditions** — show/hide operations and status entries based on contract state
- **Theme** — override accent color, background, border radius

## Wallet Authentication

When OPWallet auth is enabled:

### Roles

| Role | Can view | Can sign/broadcast | Can edit settings |
|------|---------|-------------------|------------------|
| **Admin** | Everything | Yes | Yes |
| **User** | Everything | Yes | No |
| **Everybody** | Configurable | No | No |

### Access Methods

- **Admin setup** — the first wallet to connect during setup becomes admin
- **Invite codes** — admin generates codes with max uses and expiry; new wallets redeem them to register as users
- **Session code** — pasting a DKG/signing session code bypasses wallet auth entirely (temporary access for ceremony participation)

### Session Tokens

Session tokens expire after 6 hours. The admin can toggle whether unauthenticated visitors can view the dashboard (read-only) or see only the connect page.

## Hosting

The hosting configuration defines the external URL for join links (shown when creating DKG/signing sessions):

- **Domain** — e.g., `vault.example.com`
- **Port** — defaults to 443 (HTTPS). Port 80 auto-disables SSL.
- **Path** — optional subpath, e.g., `/vault`
- **SSL** — auto-toggles based on port; configurable

This is metadata for URL building — it does not change which port the server listens on. In Docker, Caddy handles the actual reverse proxy and Let's Encrypt certificates.

## Security Model

- **Threshold ML-DSA** — FIPS 204 post-quantum signatures. No single party holds the full signing key.
- **Threshold FROST** — BIP340 Schnorr signatures via FROST (RFC 9591). The BTC wallet is threshold-controlled — no single party holds the private key.
- **Key-link binding** — FROST signature over a message binding ML-DSA and BTC keys, verified by the OPNet VM.
- **Share encryption** — AES-256-GCM with PBKDF2-derived key (600k iterations). Password never leaves the browser.
- **E2E relay** — ECDH key agreement + AES-256-GCM. Relay server only forwards ciphertext.
- **Blob integrity** — DKG phase 3 blobs include SHA-256 checksums and polynomial coefficient range validation.
- **Canonical ordering** — signing rounds enforce deterministic party ordering.
- **Broadcast locking** — server-side lock prevents double-broadcast.
- **Challenge-response auth** — ML-DSA signatures with one-time 60-second challenges.
- **Template tx approach** — sighashes captured from a template transaction, avoiding non-deterministic SDK rebuilds.
