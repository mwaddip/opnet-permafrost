# PERMAFROST Vault

Post-quantum multisig vault for [OPNet](https://opnet.org) Bitcoin L1 smart contracts.

PERMAFROST Vault is a self-hosted application that combines distributed key generation (DKG), threshold ML-DSA signing, wallet management, and OPNet transaction broadcasting into a single interface. T-of-N parties each produce their own secret share of an ML-DSA (post-quantum) signing key — without any single party ever seeing the full secret.

## How it works

### Key generation (DKG ceremony)

1. **One party creates** a session (choosing T, N, and security level).
2. **Other parties join** by pasting the session code.
3. The ceremony runs **four phases** (Commit, Reveal, Masks, Aggregate), exchanging blobs between all parties.
4. When complete, each party **downloads their encrypted share file** and independently verifies the combined public key.

### Signing

1. One party builds a transaction (contract, method, parameters) and the vault encodes it into calldata.
2. Each signing party **loads their share file** and enters their password.
3. The signing protocol runs **three rounds** of blob exchange, then combines the partial responses into a standard FIPS 204 ML-DSA signature.
4. One party **broadcasts** the signed transaction to the OPNet network. The server prevents double-broadcast — other parties see the confirmed result.

### Blob exchange

Both DKG and signing support two modes:

- **Relay mode** — an encrypted WebSocket relay routes E2E encrypted messages between parties in real time. The relay is built into the container.
- **Offline mode** — parties manually copy/paste blobs (air-gapped friendly).

## Install

### Linux (one command)

```bash
curl -sL https://github.com/mwaddip/otzi/releases/latest/download/install.sh | bash
```

Downloads the latest release, creates systemd services, and configures
nginx or apache if detected. Works with or without sudo — without sudo it
installs to `~/.permafrost/` with user-level services.

### Debian/Ubuntu (.deb)

```bash
curl -sLO https://github.com/mwaddip/otzi/releases/latest/download/permafrost-vault_*.deb
sudo dpkg -i permafrost-vault_*.deb
```

Installs to `/opt/permafrost/`, creates system user, configures nginx,
and prompts for port and domain via debconf.

### Docker

```bash
docker run -d -p 80:80 -p 443:443 -v permafrost-data:/data ghcr.io/mwaddip/otzi:latest
```

Or with Docker Compose:

```bash
git clone https://github.com/mwaddip/otzi && cd otzi && docker compose up -d
```

### Build from source

```bash
git clone https://github.com/mwaddip/otzi && cd otzi
sudo ./install.sh --deps     # install Node 20 + Go 1.23
sudo ./install.sh --build    # build and install as systemd services
```

### Windows

Download the [latest release](https://github.com/mwaddip/otzi/releases/latest)
zip, extract, and run `start.bat`. Requires [Node.js](https://nodejs.org/) in
your PATH. Open http://localhost:8080 in your browser.

### Installer options

| Command | Description |
|---------|-------------|
| `sudo ./install.sh` | Download latest release and install |
| `sudo ./install.sh --build` | Build from source and install |
| `sudo ./install.sh --deps` | Install build dependencies (Node 20, Go 1.23) |
| `sudo ./install.sh --uninstall` | Stop services, remove files |
| `sudo ./install.sh --yes` | Skip confirmation prompts |

<details>
<summary>Docker details</summary>

#### Ports

| Port | Service | Description |
|------|---------|-------------|
| **80** | Caddy | HTTP — serves the frontend and proxies `/api` + `/ws` to the backend |
| **443** | Caddy | HTTPS — active when a domain is configured with Let's Encrypt |
| **8080** | Backend | Direct access (bypasses Caddy) |

#### Custom domain and HTTPS

The Docker image includes [Caddy](https://caddyserver.com/) with automatic
Let's Encrypt HTTPS. Configure from **Settings > Hosting** in the UI, or:

```bash
curl -X POST http://localhost:8080/api/hosting \
  -H 'Content-Type: application/json' \
  -d '{"domain": "vault.example.com", "httpsEnabled": true}'
```

#### Environment variables

| Variable | Default | Description |
|----------|---------|-------------|
| `PORT` | `8080` | Backend HTTP port |
| `RELAY_PORT` | `8081` | Internal relay WebSocket port |
| `DATA_DIR` | `/data` | Persistent data directory |
| `CADDYFILE_PATH` | `/etc/caddy/Caddyfile` | Caddy configuration file |
| `XDG_DATA_HOME` | `/data/caddy` | Caddy certificate/data storage |

</details>

### Storage modes

| Mode | Description |
|------|-------------|
| **Persistent** | Config stored as plaintext JSON. For trusted environments. |
| **Encrypted Persistent** | Config encrypted with AES-256-GCM on disk. Password required on each restart. |
| **Encrypted Portable** | Config downloaded to your machine. Upload + password each session. Nothing stored on the server. |

## Architecture

```
┌─────────────────────────────────────────────────┐
│  PERMAFROST Vault                               │
│                                                 │
│  :80/:443  Web server (nginx/apache/Caddy)      │
│            └── reverse proxy ──> :8080          │
│                                                 │
│  :8080  Express backend                         │
│         ├── /api/*    REST endpoints            │
│         ├── /ws       proxied to relay :8081    │
│         └── /*        static frontend (Vite)    │
│                                                 │
│  :8081  Go relay (internal, not exposed)        │
│                                                 │
│  /var/lib/permafrost  (or /data in Docker)      │
└─────────────────────────────────────────────────┘
```

### Repository structure

```
├── src/                  # React frontend (Vite)
│   ├── components/       # DKGWizard, InstallWizard, WalletSetup,
│   │                     # SigningPage, MessageBuilder, ThresholdSign,
│   │                     # ShareGate, Settings, PasswordModal
│   └── lib/              # DKG protocol, threshold signing, relay client,
│                         # API client, crypto, share serialization
├── backend/              # Node.js/Express backend
│   └── src/
│       ├── lib/          # ConfigStore, encryption, OPNet client,
│       │                 # ThresholdMLDSASigner adapter
│       ├── routes/       # config, wallet, tx, balances, hosting
│       └── server.ts     # Express entry point + WS proxy
├── relay/                # Go WebSocket relay server
│   ├── main.go           # Entry point
│   ├── hub.go            # Session management
│   ├── session.go        # Party tracking, message routing
│   └── limits.go         # Rate limiting
├── vendor/post-quantum/  # @btc-vision/post-quantum 0.6.0-alpha.0
├── facts/                # Design by Contract interface inventory
├── install.sh            # Universal Linux installer
├── start.bat             # Windows launcher
├── Dockerfile            # Multi-stage Docker build
├── docker-compose.yml    # Docker Compose deployment
└── entrypoint.sh         # Docker entrypoint (relay + Caddy + backend)
```

## Development

Run three processes in separate terminals:

```bash
# Terminal 1: Frontend (Vite dev server on :5173)
npm install
npm run dev

# Terminal 2: Backend (Express on :8080)
npm run dev:backend

# Terminal 3: Relay (Go on :8081, needed for relay mode)
npm run dev:relay
```

The Vite dev server proxies `/api` and `/ws` to the backend on port 8080.

### Prerequisites

- Node.js 20+
- Go 1.23+

### Offline build

```bash
npm run build:offline
```

Produces a self-contained HTML file in `dist-offline/` that runs from `file://` with zero network dependency. Useful for air-gapped DKG ceremonies.

## Security

- **Post-quantum signatures**: ML-DSA (FIPS 204) via threshold signing — no single party holds the full key.
- **E2E relay encryption**: All relay messages encrypted with ECDH (P-256) + AES-256-GCM. The relay server only forwards ciphertext.
- **Share file encryption**: AES-256-GCM with PBKDF2-derived key (600k iterations, SHA-256).
- **Blob integrity**: DKG phase 3 blobs include SHA-256 checksums and polynomial coefficient range validation.
- **Canonical ordering**: Signing rounds enforce deterministic party ordering to prevent protocol divergence.
- **Broadcast locking**: Server-side lock prevents double-broadcast of the same transaction.
- **No secrets on server**: The relay holds no cryptographic material. Share passwords never leave the browser.

## Project Manifests

Any OPNet project can plug into Otzi by writing a `.otzi.json` manifest file — no custom code needed. The manifest declares contracts, operations, live state reads, conditional visibility, and optional theming. Otzi imports it and renders a fully functional operations interface with threshold signing and broadcasting built in.

### Quick example

```json
{
  "version": 1,
  "name": "My Token",
  "contracts": {
    "token": { "label": "MyToken", "abi": "OP_20" }
  },
  "reads": {
    "supply": { "contract": "token", "method": "totalSupply", "returns": "uint256", "format": "token8" }
  },
  "status": [
    { "label": "Total Supply", "read": "supply" }
  ],
  "operations": [
    {
      "id": "transfer",
      "label": "Transfer",
      "contract": "token",
      "method": "transfer",
      "params": [
        { "name": "to", "type": "address", "label": "Recipient" },
        { "name": "amount", "type": "uint256", "label": "Amount", "scale": 1e8 }
      ]
    }
  ]
}
```

Save as `my-token.otzi.json`, import in **Settings > Project Manifest**, configure the contract address, and you're signing and broadcasting transactions through threshold ML-DSA.

### What manifests can do

- **Contracts** — define any number of contracts with custom ABIs or built-in shorthands (`OP_20`, `OP_721`)
- **State reads** — poll contract values on a timer with format hints (token amounts, BTC values, percentages, prices)
- **Status panel** — dashboard showing live contract state with optional value-to-label mapping
- **Operations** — parameter inputs with auto-fill from contract addresses, settings, or live reads; scale multipliers for decimal tokens; confirmation prompts for destructive actions
- **Conditions** — show/hide operations based on contract state (equality, comparison, block windows, boolean combinators)
- **Theme** — override accent color, background, and border radius to match your project's branding

### Schema

The full JSON Schema is at [`docs/otzi-manifest-schema.json`](docs/otzi-manifest-schema.json). Use it to validate manifests or as a reference for all available fields.

### Import flow

1. Go to **Settings > Project Manifest > Import .otzi.json**
2. Select your manifest file
3. Configure contract addresses for each contract key
4. Save — operations appear on the main signing page

## License

MIT
