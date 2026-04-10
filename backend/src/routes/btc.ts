import { Router, type Request, type Response, type RequestHandler } from 'express';
import { randomBytes } from 'node:crypto';
import { Transaction, payments, address as btcAddress, toXOnly } from '@btc-vision/bitcoin';
import { ConfigStore } from '../lib/config-store.js';
import { getProvider, getNetwork } from '../lib/opnet-client.js';

// Cached unsigned tx for FROST signing (5-min TTL)
interface CachedBtcTx {
  txHex: string;
  numInputs: number;
  sighashes: Array<{ index: number; hash: string }>;
  ts: number;
}

// Fee rate cache (60s TTL)
let feeCache: { low: number; normal: number; high: number; ts: number } | null = null;

const MEMPOOL_FEES: Record<string, string> = {
  mainnet: 'https://mempool.space/api/v1/fees/recommended',
  testnet: 'https://mempool.space/signet/api/v1/fees/recommended',
};

const MEMPOOL_TX: Record<string, string> = {
  mainnet: 'https://mempool.space/api/tx',
  testnet: 'https://mempool.space/signet/api/tx',
};

export function btcRoutes(store: ConfigStore, requireUser: RequestHandler): Router {
  const r = Router();

  const txCache = new Map<string, CachedBtcTx>();
  const broadcastLock = new Map<string, { txid?: string; error?: string; ts: number }>();

  // Cleanup expired caches
  setInterval(() => {
    const cutoff = Date.now() - 5 * 60 * 1000;
    for (const [k, v] of txCache) { if (v.ts < cutoff) txCache.delete(k); }
    const bCutoff = Date.now() - 60 * 60 * 1000;
    for (const [k, v] of broadcastLock) { if (v.ts < bCutoff) broadcastLock.delete(k); }
  }, 60 * 1000);

  /** POST /api/btc/prepare — build unsigned P2TR tx, return sighashes */
  r.post('/prepare', requireUser, async (req: Request, res: Response) => {
    const { to, amount, feeRate } = req.body as {
      to: string;
      amount: number;
      feeRate: number;
    };

    try {
      if (!to || typeof to !== 'string') {
        res.status(400).json({ error: 'Missing destination address' });
        return;
      }
      if (!amount || typeof amount !== 'number' || amount <= 0 || !Number.isInteger(amount)) {
        res.status(400).json({ error: 'Amount must be a positive integer (satoshis)' });
        return;
      }
      if (!feeRate || typeof feeRate !== 'number' || feeRate <= 0) {
        res.status(400).json({ error: 'Fee rate must be a positive number (sat/vB)' });
        return;
      }

      const config = store.get();
      if (!config.permafrost?.frostP2tr || !config.permafrost?.frostUntweakedAggregateKey) {
        res.status(400).json({ error: 'No FROST keys configured' });
        return;
      }

      const networkName = config.network;
      const network = getNetwork(networkName);
      const frostP2tr = config.permafrost.frostP2tr;
      const untweakedPubKey = Buffer.from(config.permafrost.frostUntweakedAggregateKey, 'hex');
      const internalXOnly = toXOnly(untweakedPubKey as never);

      // Validate destination address
      try {
        btcAddress.toOutputScript(to, network);
      } catch {
        res.status(400).json({ error: 'Invalid destination address for this network' });
        return;
      }

      // Fetch UTXOs
      const provider = getProvider(networkName);
      const utxos = await provider.utxoManager.getUTXOs({ address: frostP2tr });

      // Coin selection: greedy, largest first
      const sorted = [...utxos].sort((a, b) => (b.value > a.value ? 1 : b.value < a.value ? -1 : 0));

      // Taproot key-path vsize: ~57.5 vB/input, ~43 vB/output (P2TR), ~10.5 overhead
      const INPUT_VBYTES = 57.5;
      const OUTPUT_VBYTES = 43;
      const OVERHEAD_VBYTES = 10.5;

      let selectedSum = 0n;
      const selectedUtxos: typeof sorted = [];

      for (const utxo of sorted) {
        selectedUtxos.push(utxo);
        selectedSum += utxo.value;

        const estVsize = Math.ceil(OVERHEAD_VBYTES + INPUT_VBYTES * selectedUtxos.length + OUTPUT_VBYTES * 2);
        const estFee = BigInt(Math.ceil(estVsize * feeRate));

        if (selectedSum >= BigInt(amount) + estFee) break;
      }

      // Calculate fee with final input count
      const hasChange = selectedSum > BigInt(amount);
      const numOutputs = hasChange ? 2 : 1;
      const vsize = Math.ceil(OVERHEAD_VBYTES + INPUT_VBYTES * selectedUtxos.length + OUTPUT_VBYTES * numOutputs);
      const fee = BigInt(Math.ceil(vsize * feeRate));

      if (selectedSum < BigInt(amount) + fee) {
        res.status(400).json({
          error: 'Insufficient funds',
          available: selectedSum.toString(),
          needed: (BigInt(amount) + fee).toString(),
        });
        return;
      }

      const change = selectedSum - BigInt(amount) - fee;

      // Build Transaction directly (key-path only — no Psbt needed)
      const tx = new Transaction();
      tx.version = 2;

      const p2trOutput = payments.p2tr({ internalPubkey: internalXOnly as never, network }).output!;

      for (const utxo of selectedUtxos) {
        // Transaction.addInput expects hash as Buffer (internal byte order = reversed txid)
        const txidBuf = Buffer.from(utxo.transactionId.replace(/^0x/, ''), 'hex').reverse();
        tx.addInput(txidBuf as never, utxo.outputIndex);
      }

      // Destination output (Satoshi is branded bigint)
      tx.addOutput(btcAddress.toOutputScript(to, network), BigInt(amount) as never);

      // Change output (skip dust: < 546 sats)
      if (change > 546n) {
        tx.addOutput(btcAddress.toOutputScript(frostP2tr, network), change as never);
      }

      // Compute sighashes for each input (Taproot key-path, SIGHASH_DEFAULT = 0x00)
      const prevoutScripts = selectedUtxos.map(() => p2trOutput);
      const prevoutValues = selectedUtxos.map(u => u.value as never);

      const sighashes: Array<{ index: number; hash: string }> = [];
      for (let i = 0; i < selectedUtxos.length; i++) {
        const hash = tx.hashForWitnessV1(i, prevoutScripts, prevoutValues, 0x00);
        sighashes.push({ index: i, hash: Buffer.from(hash).toString('hex') });
      }

      const challengeToken = randomBytes(16).toString('hex');
      txCache.set(challengeToken, {
        txHex: tx.toHex(),
        numInputs: selectedUtxos.length,
        sighashes,
        ts: Date.now(),
      });

      res.json({
        sighashes: sighashes.map(s => ({ ...s, type: 'key-path' as const })),
        challengeToken,
        estimatedFee: Number(fee),
        changeAmount: Number(change > 546n ? change : 0n),
      });
    } catch (e) {
      console.error('[btc/prepare] error:', e);
      res.status(500).json({ error: (e as Error).message });
    }
  });

  /** POST /api/btc/broadcast — inject FROST sigs and broadcast raw tx */
  r.post('/broadcast', requireUser, async (req: Request, res: Response) => {
    const { challengeToken, frostSignatures } = req.body as {
      challengeToken: string;
      frostSignatures: Array<{ index: number; signature: string }>;
    };

    try {
      if (!challengeToken) {
        res.status(400).json({ error: 'Missing challengeToken' });
        return;
      }

      // Double-broadcast prevention
      const existing = broadcastLock.get(challengeToken);
      if (existing?.txid) {
        res.json({ txid: existing.txid, alreadyBroadcast: true });
        return;
      }
      broadcastLock.set(challengeToken, { ts: Date.now() });

      const cached = txCache.get(challengeToken);
      if (!cached) {
        broadcastLock.delete(challengeToken);
        res.status(400).json({ error: 'Prepare session expired or not found — run prepare again' });
        return;
      }

      if (!Array.isArray(frostSignatures) || frostSignatures.length !== cached.numInputs) {
        broadcastLock.delete(challengeToken);
        res.status(400).json({ error: `Expected ${cached.numInputs} signatures, got ${frostSignatures?.length ?? 0}` });
        return;
      }

      // Validate all signatures are 64 bytes hex
      for (const fs of frostSignatures) {
        if (typeof fs.signature !== 'string' || !/^[0-9a-fA-F]{128}$/.test(fs.signature)) {
          broadcastLock.delete(challengeToken);
          res.status(400).json({ error: `Invalid signature at index ${fs.index}: must be 128 hex chars (64 bytes)` });
          return;
        }
      }

      // Parse cached tx and inject FROST signatures as key-path witness
      const tx = Transaction.fromHex(cached.txHex);
      for (const fs of frostSignatures) {
        const sig = Buffer.from(fs.signature, 'hex');
        // Key-path Taproot witness: single element = 64-byte Schnorr signature
        tx.setWitness(fs.index, [sig]);
      }

      const rawTx = tx.toHex();

      // Broadcast via OPNet provider (same chain as UTXO source)
      const config = store.get();
      const provider = getProvider(config.network);

      const txResult = await provider.sendRawTransaction(rawTx, false);
      if (!txResult.success) {
        throw new Error(`Broadcast failed: ${txResult.error || 'unknown'}`);
      }
      const txid = txResult.result || tx.getId();

      txCache.delete(challengeToken);
      broadcastLock.set(challengeToken, { txid, ts: Date.now() });

      console.log(`[btc/broadcast] success: ${txid}`);
      res.json({ txid });
    } catch (e) {
      console.error('[btc/broadcast] error:', e);
      broadcastLock.delete(challengeToken);
      res.status(500).json({ error: (e as Error).message });
    }
  });

  /** GET /api/btc/fees — fee rate estimates from mempool.space */
  r.get('/fees', async (_req: Request, res: Response) => {
    try {
      if (feeCache && Date.now() - feeCache.ts < 60_000) {
        res.json({ low: feeCache.low, normal: feeCache.normal, high: feeCache.high });
        return;
      }

      const config = store.get();
      const url = MEMPOOL_FEES[config.network];
      if (!url) {
        res.status(500).json({ error: `No fee API for network: ${config.network}` });
        return;
      }

      const resp = await fetch(url);
      if (!resp.ok) throw new Error(`Fee API returned ${resp.status}`);

      const data = await resp.json() as {
        fastestFee: number;
        halfHourFee: number;
        hourFee: number;
      };

      feeCache = {
        low: data.hourFee,
        normal: data.halfHourFee,
        high: data.fastestFee,
        ts: Date.now(),
      };

      res.json({ low: feeCache.low, normal: feeCache.normal, high: feeCache.high });
    } catch (e) {
      console.error('[btc/fees] error:', e);
      res.json({ low: 1, normal: 5, high: 10, fallback: true });
    }
  });

  return r;
}
