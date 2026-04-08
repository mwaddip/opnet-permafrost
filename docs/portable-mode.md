# Portable Mode

Portable mode (`encrypted-portable` storage) keeps your entire vault config in server memory only. Nothing is written to disk. The only persistent copy of your keys is the encrypted backup file you download to your own machine.

This mode is best for **air-gapped or temporary setups** where no data should remain on the server. For most use cases, prefer `persistent` or `encrypted-persistent` modes.

## What the Encrypted Config Contains

A single file holds everything your instance needs:

- **Wallet** — BTC mnemonic, P2TR address, public/tweaked keys
- **DKG shares** — threshold key material, combined ML-DSA public key, party count, threshold parameters
- **Contracts** — registered contract addresses, ABIs, methods
- **Hosting** — domain, port, HTTPS settings
- **Manifest** — project manifest config
- **Users** and invites — wallet auth mode only
- **Network** — testnet/mainnet selection

If you lose this file, **everything is unrecoverable.**

## Initial Setup Flow

1. **Install wizard:** choose network, auth mode (Admin Password or OPWallet), select **Encrypted Portable** as storage mode.
2. **Wallet generation:** generate a BTC keypair (or skip — signatures will be display-only).
3. **DKG ceremony:** complete the distributed key generation with all parties.
4. **Download your encrypted config.** A persistent banner appears at the top of every page after DKG completes. Click it, enter a password, and save the `.enc` file somewhere safe.

The banner stays visible until you click download. Do not dismiss it. If the server restarts before you download, your keys are gone.

## Returning to a Session

After a server restart, your in-memory config is wiped. The instance returns to a fresh state and shows the install wizard.

To restore:

1. Visit the instance URL.
2. On the install wizard's first step, click **Restore from Backup**.
3. Enter the password you used when downloading the config.
4. Select your `.enc` file.
5. The config loads into memory and the instance is operational again.

You will need to download the config again at the end of each session if you made changes (new contracts, manifest updates, etc.).

## How Other Users Experience It

**Password auth mode:**
Joiners do not need any password. They visit the instance URL and land directly on the signing page (assuming setup is complete). They participate in signing ceremonies by loading their own DKG share file. The admin password only protects admin operations on the backend (settings, contract management, wallet generation).

**Wallet auth mode:**
Joiners authenticate via OPWallet (ML-DSA signature), or use a session code URL the admin shares with them (`?session=CODE`). Session codes are temporary access tokens that bypass wallet authentication for a single ceremony.

In either mode, joiners only have access while the server is running and the admin's config is loaded. If the admin has not restored their config since the last server restart, joiners see the install wizard instead.

## Server Restart Behavior

When the server process restarts (crash, redeploy, host reboot):

- The in-memory config is cleared.
- `/api/status` returns `{ state: 'fresh' }`.
- Anyone visiting the URL — admin or joiner — sees the install wizard.
- The admin must restore from their encrypted backup before joiners can connect.
- Joiners who arrive before the admin restores cannot do anything useful.

There is no automatic restoration. Portable mode is single-session by design.

## Trade-offs

| Pro | Con |
|-----|-----|
| No keys on the server filesystem | Lost config file = lost keys |
| Suitable for air-gapped setups | Admin must export after every change |
| Server can be ephemeral | Joiners depend on admin being available to restore |
| No server-side encryption secrets | Single point of failure (the local backup file) |

## Recommendations

- **Back up the encrypted config in multiple places** (encrypted USB, password manager attachment, etc.)
- **Use a strong password** for the encrypted config — it's all that protects your keys
- **Test restoration** before relying on portable mode in production
- **Re-export after every change** that matters (new contract, updated manifest, added user)
- **Consider `encrypted-persistent` instead** for most use cases — same encryption, but the server stores the encrypted file so you don't need to upload it each session
