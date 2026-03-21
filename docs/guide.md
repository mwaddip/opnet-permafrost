# Ötzi User Guide

## What is Ötzi?

Ötzi (PERMAFROST Vault) is a self-hosted operations interface for OPNet Bitcoin L1 smart contracts. It combines:

- **Distributed Key Generation (DKG)** — T-of-N parties each generate a share of a post-quantum ML-DSA signing key without any single party ever seeing the full secret
- **Threshold Signing** — T parties collaborate to produce a valid signature via a 3-round protocol
- **Transaction Broadcasting** — encode calldata, simulate, sign, and broadcast OPNet contract calls
- **Project Manifests** — any OPNet project can define its operations as a declarative `.otzi.json` file

## Important: The Server Wallet

During setup, Ötzi generates a BTC wallet (mnemonic + P2TR address). This wallet exists **solely to pay transaction fees** (gas) when broadcasting signed transactions to the OPNet network.

**This is NOT the multisig vault.** The vault's signing key is the ML-DSA key from the DKG ceremony, held as shares by the participating parties. The server wallet is a separate, single-key BTC wallet used only for fee payment.

**Fund this wallet with the minimum amount needed for gas fees.** A few thousand satoshis is typically sufficient. Do not store significant value in this wallet — it is a hot wallet on the server with the mnemonic stored in the instance configuration.

The server wallet's private key (mnemonic) is:
- Stored encrypted on disk (in `encrypted-persistent` mode) or never stored (in `encrypted-portable` mode)
- Never sent to the frontend except once during initial generation for backup
- Used only at broadcast time to sign the BTC transaction envelope (not the contract call — that's the threshold ML-DSA signature)

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

### 4. Wallet Generation

Generates the BTC fee-payment wallet. **Write down the mnemonic** — it is shown only once. Fund the P2TR address with a small amount of BTC for gas fees.

### 5. DKG Ceremony

All T-of-N parties must participate simultaneously:

1. **Initiator** creates a session (chooses T, N, security level)
2. **Other parties** join by pasting the session code or clicking the join link
3. The ceremony runs 4 phases (Commit → Reveal → Masks → Aggregate)
4. Each party downloads their encrypted share file
5. The combined ML-DSA public key is saved to the instance

Blob exchange happens via the built-in encrypted WebSocket relay. All relay messages are E2E encrypted — the relay server only forwards ciphertext.

### 6. Operations

After DKG, the signing page shows available operations. If a project manifest is loaded, its operations appear with live contract state and conditional visibility.

## Signing a Transaction

1. **Build** — select an operation, fill parameters, encode calldata
2. **Sign** — each party loads their share file, enters their password, and participates in the 3-round signing protocol
3. **Broadcast** — one party broadcasts the signed transaction. Others see the result. Double-broadcast is prevented server-side.

Session codes allow parties to coordinate via the relay. The signing protocol auto-retries on norm check failures (up to 50 attempts in relay mode).

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
- **Share encryption** — AES-256-GCM with PBKDF2-derived key (600k iterations). Password never leaves the browser.
- **E2E relay** — ECDH key agreement + AES-256-GCM. Relay server only forwards ciphertext.
- **Blob integrity** — DKG phase 3 blobs include SHA-256 checksums and polynomial coefficient range validation.
- **Canonical ordering** — signing rounds enforce deterministic party ordering.
- **Broadcast locking** — server-side lock prevents double-broadcast.
- **Challenge-response auth** — ML-DSA signatures with one-time 60-second challenges.
- **Fee wallet isolation** — the server wallet only pays gas fees. Contract authorization comes from the threshold ML-DSA key.
