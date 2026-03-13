import { Router, type Request, type Response } from 'express';
import { Address } from '@btc-vision/transaction';
import { getContract, OP_20_ABI } from 'opnet';
import { ConfigStore } from '../lib/config-store.js';
import { getProvider, getNetwork } from '../lib/opnet-client.js';

export function balanceRoutes(store: ConfigStore): Router {
  const r = Router();

  /** GET /api/balances — OP-20 token balances for the Permafrost address */
  r.get('/', async (_req: Request, res: Response) => {
    try {
      const config = store.get();
      if (!config.permafrost || !config.wallet) {
        res.json({ balances: [] });
        return;
      }

      const provider = getProvider(config.network);
      const network = getNetwork(config.network);

      // Derive the OPNet address from DKG pubkey + wallet tweaked pubkey
      const opnetAddr = Address.fromString(
        config.permafrost.combinedPubKey,
        config.wallet.tweakedPubKey,
      );

      const balances: Array<{ address: string; name: string; symbol: string; balance: string; decimals: number }> = [];

      for (const c of config.contracts) {
        try {
          const contract = getContract(c.address, OP_20_ABI, provider, network);
          type ContractFnMap = Record<string, (...args: unknown[]) => Promise<{ properties: Record<string, unknown> }>>;
          const c2 = contract as unknown as ContractFnMap;
          const [nameResult, symbolResult, decimalsResult, balResult] = await Promise.all([
            c2['name']!(),
            c2['symbol']!(),
            c2['decimals']!(),
            c2['balanceOf']!(opnetAddr),
          ]);
          balances.push({
            address: c.address,
            name: nameResult.properties['name'] as string,
            symbol: symbolResult.properties['symbol'] as string,
            balance: String(balResult.properties['balance']),
            decimals: Number(decimalsResult.properties['decimals']),
          });
        } catch {
          // Skip contracts that fail (might not be OP-20)
        }
      }

      res.json({ balances });
    } catch (e) {
      res.status(500).json({ error: (e as Error).message });
    }
  });

  return r;
}
