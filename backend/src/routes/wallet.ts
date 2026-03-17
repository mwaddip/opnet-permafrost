import { Router, type Request, type Response, type RequestHandler } from 'express';
import { ConfigStore } from '../lib/config-store.js';
import { generateWallet, generateMnemonic, getProvider } from '../lib/opnet-client.js';
import { sanitizeConfig } from '../lib/types.js';

export function walletRoutes(store: ConfigStore, requireAdmin: RequestHandler): Router {
  const r = Router();

  /** POST /api/wallet/generate — create BTC keypair, save to config */
  r.post('/generate', requireAdmin, (req: Request, res: Response) => {
    try {
      const config = store.get();
      const phrase = generateMnemonic();
      const { wallet, mnemonic } = generateWallet(phrase, config.network);

      store.update({
        wallet: {
          mnemonic: phrase,
          p2tr: wallet.p2tr,
          tweakedPubKey: Buffer.from(wallet.tweakedPubKeyKey).toString('hex'),
          publicKey: Buffer.from(wallet.publicKey).toString('hex'),
        },
        setupState: { ...config.setupState, walletSkipped: false },
      });

      // Cleanup sensitive material
      mnemonic.zeroize();
      wallet.zeroize();

      const updated = store.get();
      // Return mnemonic ONE TIME for the backup display. It's never returned again.
      res.json({ ok: true, mnemonic: phrase, config: sanitizeConfig(updated) });
    } catch (e) {
      res.status(500).json({ error: (e as Error).message });
    }
  });

  /** POST /api/wallet/skip — mark wallet as skipped */
  r.post('/skip', requireAdmin, (req: Request, res: Response) => {
    const { dontShowAgain } = req.body as { dontShowAgain?: boolean };
    try {
      const config = store.get();
      store.update({
        setupState: {
          ...config.setupState,
          walletSkipped: true,
          walletDontShowAgain: dontShowAgain ?? false,
        },
      });
      res.json({ ok: true });
    } catch (e) {
      res.status(500).json({ error: (e as Error).message });
    }
  });

  /** GET /api/wallet/balance — BTC balance in satoshis */
  r.get('/balance', async (req: Request, res: Response) => {
    try {
      const config = store.get();
      if (!config.wallet) {
        res.json({ balance: 0, configured: false });
        return;
      }
      const provider = getProvider(config.network);
      const balance = await provider.getBalance(config.wallet.p2tr, true);
      res.json({ balance: balance.toString(), configured: true });
    } catch (e) {
      res.status(500).json({ error: (e as Error).message });
    }
  });

  return r;
}
