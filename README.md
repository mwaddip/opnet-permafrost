# PERMAFROST Vault

Post-quantum multisig operations toolkit for [OPNet](https://opnet.org) Bitcoin L1 smart contracts.

PERMAFROST Vault is a self-hosted Docker container that combines DKG key generation, threshold ML-DSA signing, wallet management, and OPNet transaction broadcasting into a single operational interface. It runs a distributed key generation (DKG) protocol so that **T-of-N parties** each produce their own secret share of an ML-DSA (post-quantum) signing key — without any single party ever seeing the full secret.

## How it works

1. **One party creates** a ceremony session (choosing T, N, and security level).
2. **Other parties join** by pasting the session config blob or scanning a relay link.
3. The ceremony runs **four phases** (Commit → Reveal → Masks → Aggregate), exchanging blobs between all parties.
4. When complete, each party **downloads their encrypted share file** and independently verifies the combined public key.

Blob exchange can happen in two ways:

- **Offline mode** — parties manually copy/paste blobs between browser windows (air-gapped friendly).
- **Relay mode** — an encrypted WebSocket relay routes E2E encrypted messages between parties in real time. The relay server never sees plaintext — it only forwards ciphertext.

## Repository structure

```
├── src/                  # React frontend (Vite)
│   ├── components/       # DKGWizard, InstallWizard, WalletSetup,
│   │                     # SigningPage, MessageBuilder, ThresholdSign,
│   │                     # ShareGate, Settings, PasswordModal
│   ├── lib/              # DKG protocol, threshold signing, relay client,
│   │                     # API client, crypto helpers, vault types
│   └── styles/           # CSS (dark theme, neutral blue accent)
├── backend/              # Node.js/Express backend
│   └── src/
│       ├── lib/          # ConfigStore, encryption, OPNet client,
│       │                 # ThresholdMLDSASigner adapter
│       ├── routes/       # API routes (config, wallet, tx, balances)
│       └── server.ts     # Express entry point + WS proxy
├── relay/                # Go WebSocket relay server
│   ├── main.go           # Entry point, CLI flags, env vars
│   ├── hub.go            # Session management, WebSocket upgrade
│   ├── session.go        # Per-session party tracking, message routing
│   ├── limits.go         # Rate limiting (per-IP, max sessions)
│   ├── Dockerfile        # Minimal scratch-based container
│   └── *_test.go         # Integration tests
├── vendor/post-quantum/  # @btc-vision/post-quantum (threshold ML-DSA)
├── Dockerfile            # Multi-stage build (frontend + backend + relay)
├── docker-compose.yml    # Single-container deployment
└── entrypoint.sh         # Container startup (relay + backend)
```

## Setup

### Prerequisites

- Node.js 20+
- Go 1.23+ (for the relay server)

### Ceremony app (frontend)

```bash
npm install
npm run dev          # dev server on http://localhost:5173
npm run build        # production build → dist/
npm run build:offline  # single-file HTML → dist-offline/
```

The offline build produces a self-contained HTML file that runs from `file://` with zero network dependency.

### Relay server

The relay server is a single Go binary. Build and run it directly:

```bash
cd relay
go build -o relay .
./relay                           # listens on :8080
./relay -addr :9090               # custom port
./relay -base-url https://example.com/ceremony  # session links include this URL
```

Or with Docker:

```bash
cd relay
docker build -t permafrost-relay .
docker run -p 8080:8080 permafrost-relay
```

#### Environment variables

| Variable | Default | Description |
|---|---|---|
| `RELAY_ADDR` | `:8080` | Listen address |
| `RELAY_BASE_URL` | (empty) | Base URL for shareable session links |
| `RELAY_MAX_SESSIONS` | `50` | Max concurrent sessions |
| `RELAY_MAX_PARTIES` | `10` | Max parties per session |
| `RELAY_MAX_MESSAGE` | `1048576` | Max WebSocket message size (bytes) |
| `RELAY_MAX_PER_IP` | `5` | Max connections per IP |
| `RELAY_PING_INTERVAL` | `30` | WebSocket ping interval (seconds) |
| `RELAY_ABANDON_TIMEOUT` | `600` | Cleanup abandoned sessions after (seconds) |

### Connecting the app to your relay

Set the `VITE_RELAY_URL` environment variable before building the ceremony app:

```bash
VITE_RELAY_URL=wss://your-server.com/ws npm run build
```

If unset, the app defaults to `ws://localhost:8080/ws`.

## Deploying on a web server

A typical production setup uses a reverse proxy (nginx/Caddy) in front of both the static ceremony app and the relay WebSocket server.

### With nginx

```nginx
server {
    listen 443 ssl;
    server_name ceremony.example.com;

    # Ceremony app (static files)
    location / {
        root /var/www/permafrost/dist;
        try_files $uri /index.html;
    }

    # Relay WebSocket
    location /ws {
        proxy_pass http://127.0.0.1:8080;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_read_timeout 3600s;
    }
}
```

Build and deploy:

```bash
# Build the ceremony app pointing to your relay
VITE_RELAY_URL=wss://ceremony.example.com/ws npm run build

# Copy dist/ to your web root
cp -r dist/* /var/www/permafrost/dist/

# Run the relay server
cd relay && go build -o relay .
RELAY_BASE_URL=https://ceremony.example.com ./relay
```

### With Caddy

```
ceremony.example.com {
    handle /ws {
        reverse_proxy localhost:8080
    }
    handle {
        root * /var/www/permafrost/dist
        file_server
        try_files {path} /index.html
    }
}
```

### With Docker Compose

```yaml
services:
  relay:
    build: ./relay
    environment:
      - RELAY_BASE_URL=https://ceremony.example.com
    ports:
      - "8080:8080"
```

## Vault — Docker Deployment

The Vault packages the frontend, backend, and relay into a single Docker container.

### Quick start

```bash
docker compose up -d
# Open http://localhost:8080
```

The install wizard will guide you through network selection, storage mode, wallet generation, and the DKG ceremony.

### Build from source

```bash
docker build -t permafrost-vault .
docker run -d -p 8080:8080 -v permafrost-data:/data permafrost-vault
```

### Storage modes

| Mode | Description |
|---|---|
| **Persistent** | Config stored as plaintext JSON at `/data/config.json`. Fast access for trusted environments. |
| **Encrypted Persistent** | Config encrypted with AES-256-GCM on disk. Password required on each container restart. |
| **Encrypted Portable** | Config file downloaded to your machine. Upload + password each session. Nothing persisted on server. |

### Backend environment variables

| Variable | Default | Description |
|---|---|---|
| `PORT` | `8080` | HTTP listen port |
| `RELAY_PORT` | `8081` | Internal relay WebSocket port |
| `DATA_DIR` | `/data` | Persistent data directory |

## Vault — Development Setup

Run three processes in separate terminals:

```bash
# Terminal 1: Frontend (Vite dev server on :5173)
npm run dev

# Terminal 2: Backend (Express on :8080, auto-reload)
npm run dev:backend

# Terminal 3: Relay (Go on :8081, optional — needed for relay mode)
npm run dev:relay
```

The Vite dev server proxies `/api` and `/ws` to the backend on port 8080.

## Security

- **E2E encryption**: All relay messages are encrypted with ECDH (P-256) + AES-256-GCM. The relay server only forwards ciphertext.
- **Session fingerprint**: Parties can compare an 8-character fingerprint out-of-band to detect MITM attacks on the relay.
- **Offline mode**: For maximum security, run the offline build from a local file — no server trust required.
- **Share files**: Each share is encrypted with AES-256-GCM using a password-derived key (PBKDF2, 100k iterations) before download.
- **No secrets on server**: The relay server holds no cryptographic material. Compromising it cannot leak shares or forge signatures.

## License

MIT
