import { Router, type Request, type Response } from 'express';
import { createHash } from 'node:crypto';
import { Address, BinaryWriter } from '@btc-vision/transaction';
import { getContract, OP_20_ABI } from 'opnet';
import { ConfigStore } from '../lib/config-store.js';
import { getProvider, getNetwork, generateWallet } from '../lib/opnet-client.js';
import { ThresholdMLDSASigner } from '../lib/threshold-signer.js';

export function txRoutes(store: ConfigStore): Router {
  const r = Router();

  // Broadcast lock: messageHash → result (prevents double-broadcast)
  const broadcastResults = new Map<string, { transactionId?: string; estimatedFees?: string; error?: string }>();

  /** GET /api/tx/broadcast-status/:messageHash — check if already broadcast */
  r.get('/broadcast-status/:messageHash', (req: Request, res: Response) => {
    const cached = broadcastResults.get(req.params.messageHash!);
    if (cached) {
      res.json({ broadcast: true, ...cached });
    } else {
      res.json({ broadcast: false });
    }
  });

  /** POST /api/tx/encode — encode calldata from method + params */
  r.post('/encode', async (req: Request, res: Response) => {
    const { method, params, paramTypes } = req.body as {
      method: string;
      params: string[];
      paramTypes: Array<'address' | 'u256' | 'bytes'>;
    };
    try {
      // Compute 4-byte selector: SHA256(methodName) first 4 bytes
      const selectorInput = new TextEncoder().encode(method);
      const selectorHash = createHash('sha256').update(selectorInput).digest();
      const selector = selectorHash.subarray(0, 4);

      const writer = new BinaryWriter();
      writer.writeBytes(selector);

      for (let i = 0; i < params.length; i++) {
        const value = params[i]!;
        const type = paramTypes[i]!;
        if (type === 'address') {
          // Address is 32 bytes (SHA256 of ML-DSA pubkey or tweaked pubkey)
          const addrBytes = Buffer.from(value.replace(/^0x/, ''), 'hex');
          writer.writeBytes(addrBytes);
        } else if (type === 'u256') {
          writer.writeU256(BigInt(value));
        } else {
          writer.writeBytes(Buffer.from(value.replace(/^0x/, ''), 'hex'));
        }
      }

      const calldata = writer.getBuffer();
      const calldataHex = Buffer.from(calldata).toString('hex');

      // Compute message hash for display
      const msgHash = createHash('sha256').update(calldata).digest('hex');

      res.json({ calldata: calldataHex, messageHash: msgHash });
    } catch (e) {
      res.status(400).json({ error: (e as Error).message });
    }
  });

  /** POST /api/tx/simulate — simulate a contract call */
  r.post('/simulate', async (req: Request, res: Response) => {
    const { contract: contractAddr, method, params: rawParams, paramTypes, abi } = req.body as {
      contract: string;
      method: string;
      params: unknown[];
      paramTypes?: Array<'address' | 'u256' | 'bytes'>;
      abi?: unknown;
    };
    try {
      const config = store.get();
      const provider = getProvider(config.network);
      const network = getNetwork(config.network);
      const contractAbi = abi || OP_20_ABI;

      // Convert params to proper types expected by OPNet SDK
      const params = (rawParams ?? []).map((val, i) => {
        const t = paramTypes?.[i];
        const s = String(val);
        if (t === 'address') return Address.wrap(Buffer.from(s.replace(/^0[xX]/, ''), 'hex'));
        if (t === 'u256') return BigInt(s);
        return val;
      });

      const contract = getContract(contractAddr, contractAbi as never, provider, network);
      const fn = (contract as unknown as Record<string, unknown>)[method];
      if (typeof fn !== 'function') {
        res.status(400).json({ error: `Method '${method}' not found on contract` });
        return;
      }

      const result = await (fn as (...args: unknown[]) => Promise<{ revert?: string; estimatedGas?: bigint; events?: unknown[] }>).call(contract, ...params);
      if (result.revert) {
        res.json({ success: false, revert: result.revert });
        return;
      }

      res.json({
        success: true,
        estimatedGas: result.estimatedGas?.toString(),
        events: result.events,
      });
    } catch (e) {
      res.status(500).json({ error: (e as Error).message });
    }
  });

  /** POST /api/tx/broadcast — build tx with ML-DSA sig and broadcast */
  r.post('/broadcast', async (req: Request, res: Response) => {
    const { contract: contractAddr, method, params: rawParams, paramTypes, abi, signature, messageHash } = req.body as {
      contract: string;
      method: string;
      params: unknown[];
      paramTypes?: Array<'address' | 'u256' | 'bytes'>;
      abi?: unknown;
      signature: string;
      messageHash?: string;
    };

    // Prevent double-broadcast
    if (messageHash) {
      const cached = broadcastResults.get(messageHash);
      if (cached) {
        res.json({ success: !!cached.transactionId, alreadyBroadcast: true, ...cached });
        return;
      }
      // Lock immediately to block concurrent requests
      broadcastResults.set(messageHash, {});
    }

    // Convert params to proper types expected by OPNet SDK
    const params = (rawParams ?? []).map((val, i) => {
      const t = paramTypes?.[i];
      const s = String(val);
      if (t === 'address') return Address.wrap(Buffer.from(s.replace(/^0[xX]/, ''), 'hex'));
      if (t === 'u256') return BigInt(s);
      return val;
    });
    try {
      const config = store.get();
      if (!config.wallet) {
        res.status(400).json({ error: 'No wallet configured' });
        return;
      }
      if (!config.permafrost) {
        res.status(400).json({ error: 'No DKG ceremony completed' });
        return;
      }

      const provider = getProvider(config.network);
      const network = getNetwork(config.network);
      const contractAbi = abi || OP_20_ABI;

      // Reconstruct wallet from mnemonic
      const { wallet, mnemonic } = generateWallet(config.wallet.mnemonic, config.network);

      // Use the Permafrost vault address (DKG pubkey + tweaked pubkey) as sender
      const vaultAddr = Address.fromString(
        config.permafrost.combinedPubKey,
        config.wallet.tweakedPubKey,
      );
      const contract = getContract(contractAddr, contractAbi as never, provider, network, vaultAddr);
      const fn = (contract as unknown as Record<string, unknown>)[method];
      if (typeof fn !== 'function') {
        mnemonic.zeroize();
        wallet.zeroize();
        res.status(400).json({ error: `Method '${method}' not found` });
        return;
      }

      const callResult = await (fn as (...args: unknown[]) => Promise<{ revert?: string; sendTransaction: (params: unknown) => Promise<{ transactionId: string; estimatedFees?: bigint }> }>).call(contract, ...(params ?? []));
      if (callResult.revert) {
        mnemonic.zeroize();
        wallet.zeroize();
        res.status(400).json({ error: `Simulation reverted: ${callResult.revert}` });
        return;
      }

      // Obtain challenge solution (PoW required by OPNet)
      const challenge = await provider.getChallenge();

      // Create ThresholdMLDSASigner with pre-computed signature
      const sigBytes = Buffer.from(signature, 'hex');
      const pubKeyBytes = Buffer.from(config.permafrost.combinedPubKey, 'hex');
      const thresholdSigner = new ThresholdMLDSASigner(sigBytes, pubKeyBytes);

      // Send transaction
      const receipt = await callResult.sendTransaction({
        signer: wallet.keypair,
        mldsaSigner: thresholdSigner,
        refundTo: config.wallet.p2tr,
        network,
        feeRate: 10,
        priorityFee: 1000n,
        maximumAllowedSatToSpend: 100000n,
        challenge,
      });

      mnemonic.zeroize();
      wallet.zeroize();

      const result = {
        transactionId: receipt.transactionId,
        estimatedFees: receipt.estimatedFees?.toString(),
      };
      if (messageHash) broadcastResults.set(messageHash, result);

      res.json({ success: true, ...result });
    } catch (e) {
      const errResult = { error: (e as Error).message };
      // On error, clear the lock so it can be retried
      if (messageHash) broadcastResults.delete(messageHash);
      res.status(500).json(errResult);
    }
  });

  return r;
}
