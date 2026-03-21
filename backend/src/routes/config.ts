import { Router, type Request, type Response, type RequestHandler } from 'express';
import { ConfigStore } from '../lib/config-store.js';
import type { UserStore } from '../lib/users.js';
import { sanitizeConfig, type NetworkName, type StorageMode } from '../lib/types.js';
import { hashPassword, verifyPassword, createToken, getTokenInfo } from '../lib/auth.js';
import { encryptConfig, decryptConfig } from '../lib/encryption.js';

export function configRoutes(store: ConfigStore, userStore: UserStore, requireAdmin: RequestHandler): Router {
  const r = Router();

  /** GET /api/status — returns setup state + storage mode */
  r.get('/status', (_req: Request, res: Response) => {
    if (!store.isInitialized()) {
      res.json({ state: 'fresh' });
      return;
    }
    try {
      const config = store.get();
      const { setupState, storageMode, network } = config;
      const walletConfigured = !!config.wallet;
      res.json({ state: 'ready', setupState, storageMode, network, walletConfigured, authMode: config.authMode || 'password' });
    } catch {
      // Initialized but not loaded (encrypted-persistent, needs unlock)
      res.json({ state: 'locked' });
    }
  });

  /** POST /api/init — first-time setup */
  r.post('/init', (req: Request, res: Response) => {
    const { network, storageMode, password, adminPassword, authMode, walletAddress, walletLabel } = req.body as {
      network: NetworkName;
      storageMode: StorageMode;
      password?: string;
      adminPassword?: string;
      authMode?: 'password' | 'wallet';
      walletAddress?: string;
      walletLabel?: string;
    };
    if (!network || !storageMode) {
      res.status(400).json({ error: 'network and storageMode required' });
      return;
    }
    if (storageMode === 'encrypted-persistent' && !password) {
      res.status(400).json({ error: 'password required for encrypted-persistent mode' });
      return;
    }

    const resolvedAuthMode = authMode || 'password';

    if (resolvedAuthMode === 'password') {
      if (!adminPassword) {
        res.status(400).json({ error: 'adminPassword required' });
        return;
      }
    } else {
      if (!walletAddress) {
        res.status(400).json({ error: 'walletAddress required for wallet auth mode' });
        return;
      }
    }

    try {
      store.init(network, storageMode, password);

      if (resolvedAuthMode === 'password') {
        store.update({ adminPasswordHash: hashPassword(adminPassword!), authMode: 'password' }, password);
        res.json({ ok: true });
      } else {
        store.update({ authMode: 'wallet' }, password);
        userStore.addUser(walletAddress!, 'admin', walletLabel || 'Admin');
        // Return a session token immediately — the admin just proved their identity during setup
        const token = createToken('admin', walletAddress!);
        res.json({ ok: true, token, role: 'admin', address: walletAddress });
      }
    } catch (e) {
      res.status(409).json({ error: (e as Error).message });
    }
  });

  /** POST /api/unlock — decrypt encrypted-persistent config */
  r.post('/unlock', (req: Request, res: Response) => {
    const { password } = req.body as { password: string };
    if (!password) {
      res.status(400).json({ error: 'password required' });
      return;
    }
    try {
      store.load(password);
      const config = store.get();
      res.json({ ok: true, config: sanitizeConfig(config) });
    } catch {
      res.status(401).json({ error: 'Wrong password or corrupted config' });
    }
  });

  /** POST /api/admin/unlock — verify admin password, return session token */
  r.post('/admin/unlock', (req: Request, res: Response) => {
    const { password } = req.body as { password: string };
    if (!password) {
      res.status(400).json({ error: 'password required' });
      return;
    }
    try {
      const config = store.get();
      if (!config.adminPasswordHash) {
        res.status(400).json({ error: 'No admin password set' });
        return;
      }
      if (!verifyPassword(password, config.adminPasswordHash)) {
        res.status(401).json({ error: 'Wrong admin password' });
        return;
      }
      const token = createToken('password-admin');
      res.json({ ok: true, token });
    } catch (e) {
      res.status(503).json({ error: (e as Error).message });
    }
  });

  /** GET /api/config — sanitized config (no private keys) */
  r.get('/config', (_req: Request, res: Response) => {
    try {
      res.json(sanitizeConfig(store.get()));
    } catch (e) {
      res.status(503).json({ error: (e as Error).message });
    }
  });

  /** POST /api/config/contracts — update contract configuration */
  r.post('/config/contracts', requireAdmin, (req: Request, res: Response) => {
    const { contracts } = req.body;
    if (!Array.isArray(contracts)) {
      res.status(400).json({ error: 'contracts must be an array' });
      return;
    }
    for (const c of contracts) {
      if (typeof c !== 'object' || !c) { res.status(400).json({ error: 'each contract must be an object' }); return; }
      if (typeof c.name !== 'string' || !c.name) { res.status(400).json({ error: 'contract name required' }); return; }
      if (typeof c.address !== 'string' || !c.address) { res.status(400).json({ error: 'contract address required' }); return; }
      if (!Array.isArray(c.methods)) { res.status(400).json({ error: 'contract methods must be an array' }); return; }
    }
    try {
      store.update({ contracts });
      res.json({ ok: true });
    } catch (e) {
      res.status(500).json({ error: (e as Error).message });
    }
  });

  /** POST /api/config/export — export config for portable mode */
  r.post('/config/export', (_req: Request, res: Response) => {
    try {
      res.json({ config: store.exportConfig() });
    } catch (e) {
      res.status(500).json({ error: (e as Error).message });
    }
  });

  /** POST /api/config/import — import portable config (decrypted by frontend) */
  r.post('/config/import', requireAdmin, (req: Request, res: Response) => {
    const { config } = req.body;
    if (!config) {
      res.status(400).json({ error: 'config required' });
      return;
    }
    try {
      store.importPortable(typeof config === 'string' ? JSON.parse(config) : config);
      res.json({ ok: true, config: sanitizeConfig(store.get()) });
    } catch (e) {
      res.status(400).json({ error: (e as Error).message });
    }
  });

  /** POST /api/dkg/save — save DKG ceremony result */
  r.post('/dkg/save', requireAdmin, (req: Request, res: Response) => {
    const { threshold, parties, level, combinedPubKey, shareData } = req.body;
    if (typeof threshold !== 'number' || threshold < 1) { res.status(400).json({ error: 'invalid threshold' }); return; }
    if (typeof parties !== 'number' || parties < threshold) { res.status(400).json({ error: 'invalid parties' }); return; }
    if (typeof level !== 'number' || ![44, 65, 87, 128, 192, 256].includes(level)) { res.status(400).json({ error: 'invalid level' }); return; }
    if (typeof combinedPubKey !== 'string' || !/^[0-9a-fA-F]+$/.test(combinedPubKey)) { res.status(400).json({ error: 'invalid combinedPubKey' }); return; }
    if (typeof shareData !== 'string') { res.status(400).json({ error: 'invalid shareData' }); return; }
    try {
      const config = store.get();
      store.update({
        permafrost: { threshold, parties, level, combinedPubKey, shareData },
        setupState: { ...config.setupState, dkgComplete: true },
      });
      res.json({ ok: true });
    } catch (e) {
      res.status(500).json({ error: (e as Error).message });
    }
  });

  /** GET /api/manifest — get current manifest config */
  r.get('/manifest', (_req: Request, res: Response) => {
    try {
      const config = store.get();
      res.json({ manifestConfig: config.manifestConfig || null });
    } catch (e) {
      res.status(503).json({ error: (e as Error).message });
    }
  });

  /** POST /api/manifest — save manifest config */
  r.post('/manifest', requireAdmin, (req: Request, res: Response) => {
    const { manifestConfig } = req.body;
    // Allow null (remove manifest) or validate structure
    if (manifestConfig !== null && manifestConfig !== undefined) {
      if (typeof manifestConfig !== 'object') { res.status(400).json({ error: 'manifestConfig must be an object or null' }); return; }
      const mc = manifestConfig as Record<string, unknown>;
      if (!mc.manifest || typeof mc.manifest !== 'object') { res.status(400).json({ error: 'manifestConfig.manifest required' }); return; }
      const m = mc.manifest as Record<string, unknown>;
      if (m.version !== 1) { res.status(400).json({ error: 'unsupported manifest version' }); return; }
      if (typeof m.name !== 'string' || !m.name) { res.status(400).json({ error: 'manifest name required' }); return; }
      if (!m.contracts || typeof m.contracts !== 'object') { res.status(400).json({ error: 'manifest contracts required' }); return; }
      if (!Array.isArray(m.operations)) { res.status(400).json({ error: 'manifest operations required' }); return; }
    }
    try {
      store.update({ manifestConfig });
      res.json({ ok: true });
    } catch (e) {
      res.status(500).json({ error: (e as Error).message });
    }
  });

  /** POST /api/backup — encrypted backup (config + users) */
  r.post('/backup', requireAdmin, (req: Request, res: Response) => {
    const { password } = req.body as { password?: string };
    if (!password) {
      res.status(400).json({ error: 'password required' });
      return;
    }
    try {
      const config = store.get();
      const users = userStore.listUsers();
      const invites = userStore.listInvites();
      const everybodyCanRead = userStore.getEverybodyCanRead();
      const backup = {
        version: 1,
        timestamp: Date.now(),
        config,
        users: { users, invites, settings: { everybodyCanRead } },
      };
      const encrypted = encryptConfig(JSON.stringify(backup), password);
      res.json({ encrypted });
    } catch (e) {
      res.status(500).json({ error: (e as Error).message });
    }
  });

  /** POST /api/restore — decrypt and restore from encrypted backup */
  r.post('/restore', (req: Request, res: Response) => {
    const isFresh = !store.isInitialized();
    if (!isFresh) {
      // Require valid admin token on initialized instances
      const auth = req.headers.authorization;
      if (!auth?.startsWith('Bearer ')) {
        res.status(401).json({ error: 'Admin authentication required' });
        return;
      }
      const tokenInfo = getTokenInfo(auth.slice(7));
      if (!tokenInfo || (tokenInfo.role !== 'admin' && tokenInfo.role !== 'password-admin')) {
        res.status(401).json({ error: 'Invalid or expired admin token' });
        return;
      }
    }
    const { encrypted, password } = req.body as { encrypted?: string; password?: string };
    if (!encrypted || !password) {
      res.status(400).json({ error: 'encrypted and password required' });
      return;
    }
    let backup: { config?: unknown; users?: { users?: unknown[]; invites?: unknown[]; settings?: { everybodyCanRead?: boolean } } };
    try {
      backup = JSON.parse(decryptConfig(encrypted, password));
    } catch {
      res.status(401).json({ error: 'Wrong password or corrupted backup' });
      return;
    }
    if (!backup?.config) {
      res.status(400).json({ error: 'Invalid backup format' });
      return;
    }
    try {
      const config = backup.config as import('../lib/types.js').VaultConfig;
      if (isFresh) {
        store.init(config.network, config.storageMode);
      }
      store.update(config);

      if (backup.users?.users && Array.isArray(backup.users.users)) {
        for (const u of backup.users.users as Array<{ address: string; role: 'admin' | 'user'; label: string }>) {
          if (!userStore.getUser(u.address)) {
            userStore.addUser(u.address, u.role, u.label);
          }
        }
      }
      if (backup.users?.settings?.everybodyCanRead !== undefined) {
        userStore.setEverybodyCanRead(backup.users.settings.everybodyCanRead);
      }

      res.json({ ok: true });
    } catch (e) {
      res.status(500).json({ error: (e as Error).message });
    }
  });

  /** POST /api/reset — wipe everything */
  r.post('/reset', requireAdmin, (req: Request, res: Response) => {
    const { confirm } = req.body as { confirm: string };
    if (confirm !== 'RESET') {
      res.status(400).json({ error: 'Send { confirm: "RESET" } to confirm' });
      return;
    }
    store.reset();
    res.json({ ok: true });
  });

  return r;
}
