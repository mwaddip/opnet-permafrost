import { Router, type Request, type Response, type RequestHandler } from 'express';
import { ConfigStore } from '../lib/config-store.js';
import { sanitizeConfig, type NetworkName, type StorageMode } from '../lib/types.js';
import { hashPassword, verifyPassword, createToken } from '../lib/auth.js';

export function configRoutes(store: ConfigStore, requireAdmin: RequestHandler): Router {
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
      res.json({ state: 'ready', setupState, storageMode, network, walletConfigured });
    } catch {
      // Initialized but not loaded (encrypted-persistent, needs unlock)
      res.json({ state: 'locked' });
    }
  });

  /** POST /api/init — first-time setup */
  r.post('/init', (req: Request, res: Response) => {
    const { network, storageMode, password, adminPassword } = req.body as {
      network: NetworkName;
      storageMode: StorageMode;
      password?: string;
      adminPassword?: string;
    };
    if (!network || !storageMode) {
      res.status(400).json({ error: 'network and storageMode required' });
      return;
    }
    if (storageMode === 'encrypted-persistent' && !password) {
      res.status(400).json({ error: 'password required for encrypted-persistent mode' });
      return;
    }
    if (!adminPassword) {
      res.status(400).json({ error: 'adminPassword required' });
      return;
    }
    try {
      store.init(network, storageMode, password);
      store.update({ adminPasswordHash: hashPassword(adminPassword) }, password);
      res.json({ ok: true });
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
      const token = createToken();
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
