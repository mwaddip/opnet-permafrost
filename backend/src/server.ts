import express from 'express';
import { createProxyMiddleware } from 'http-proxy-middleware';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { ConfigStore } from './lib/config-store.js';
import { UserStore } from './lib/users.js';
import { createAuthMiddleware } from './lib/auth.js';
import { configRoutes } from './routes/config.js';
import { walletRoutes } from './routes/wallet.js';
import { txRoutes } from './routes/tx.js';
import { balanceRoutes } from './routes/balances.js';
import { hostingRoutes } from './routes/hosting.js';
import { authRoutes } from './routes/auth.js';
import { userRoutes, inviteRoutes } from './routes/users.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const PORT = parseInt(process.env.PORT || '8080', 10);
const RELAY_PORT = parseInt(process.env.RELAY_PORT || '8081', 10);

const store = new ConfigStore();
const userStore = new UserStore();
const app = express();

app.use(express.json({ limit: '10mb' }));

// Try to auto-load persistent config on startup
try { store.load(); } catch { /* not initialized or encrypted — that's fine */ }

// Auth middleware
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

// Relay session count (proxied from relay /sessions endpoint)
app.get('/api/relay/sessions', async (_req, res) => {
  try {
    const resp = await fetch(`http://127.0.0.1:${RELAY_PORT}/sessions`);
    const data = await resp.json();
    res.json(data);
  } catch {
    res.json({ active: 0 });
  }
});

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

// Wire WebSocket upgrade to the proxy
server.on('upgrade', wsProxy.upgrade);

// Export for route registration by other modules
export { store };
