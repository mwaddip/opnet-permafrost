import { Router, type Request, type Response, type RequestHandler } from 'express';
import { createHash } from 'node:crypto';
import { Address, BinaryWriter } from '@btc-vision/transaction';
import { toXOnly, tapTweakHash } from '@btc-vision/bitcoin';
import { getContract, OP_20_ABI } from 'opnet';
import { ConfigStore } from '../lib/config-store.js';
import { getProvider, getNetwork, generateWallet } from '../lib/opnet-client.js';
import { ThresholdMLDSASigner } from '../lib/threshold-signer.js';
import { FrostPsbtSigner } from '../lib/frost-psbt-signer.js';

// Normalize manifest ABI entries to match opnet SDK format
const ABI_TYPE_MAP: Record<string, string> = {
  uint256: 'UINT256', uint8: 'UINT8', uint16: 'UINT16', uint32: 'UINT32',
  address: 'ADDRESS', bool: 'BOOL', bytes: 'BYTES', string: 'STRING',
};

// Shorthand → full ABI from the opnet SDK
const ABI_SHORTHANDS: Record<string, typeof OP_20_ABI> = {
  OP_20: OP_20_ABI,
  OP_20S: OP_20_ABI, // extend later
};

function normalizeAbiEntry(entry: unknown): unknown[] {
  // Expand shorthand strings ("OP_20" → full ABI array)
  if (typeof entry === 'string') {
    return ABI_SHORTHANDS[entry] ?? [];
  }
  if (typeof entry !== 'object' || !entry) return [entry];
  const e = entry as Record<string, unknown>;
  return [{
    ...e,
    type: typeof e.type === 'string' ? e.type.toLowerCase() : e.type,
    constant: (e.inputs as unknown[] | undefined)?.length === 0,
    inputs: Array.isArray(e.inputs) ? e.inputs.map((inp: Record<string, unknown>) => ({
      ...inp, type: ABI_TYPE_MAP[String(inp.type).toLowerCase()] || String(inp.type).toUpperCase(),
    })) : e.inputs,
    outputs: Array.isArray(e.outputs) ? e.outputs.map((out: Record<string, unknown>) => ({
      ...out, type: ABI_TYPE_MAP[String(out.type).toLowerCase()] || String(out.type).toUpperCase(),
    })) : e.outputs,
  }];
}

function resolveAbi(abi: unknown): unknown[] {
  if (!abi) return OP_20_ABI;
  const raw = Array.isArray(abi) ? abi : [abi];
  return raw.flatMap(normalizeAbiEntry);
}

// Transaction fee defaults
const TX_FEE_RATE = parseInt(process.env.TX_FEE_RATE || '10', 10);
const TX_PRIORITY_FEE = BigInt(process.env.TX_PRIORITY_FEE || '1000');
const TX_MAX_SAT_SPEND = BigInt(process.env.TX_MAX_SAT_SPEND || '100000');

export function txRoutes(store: ConfigStore, requireUser: RequestHandler, requireAdmin: RequestHandler): Router {
  const r = Router();

  // Broadcast lock: messageHash → result (prevents double-broadcast)
  const broadcastResults = new Map<string, { transactionId?: string; estimatedFees?: string; error?: string; _ts?: number }>();

  // Clean up old broadcast results every 10 minutes (keep for 1 hour)
  setInterval(() => {
    const cutoff = Date.now() - 60 * 60 * 1000;
    for (const [key, val] of broadcastResults) {
      if ((val._ts ?? 0) < cutoff) broadcastResults.delete(key);
    }
  }, 10 * 60 * 1000);

  /** GET /api/tx/block-height — current block height */
  r.get('/block-height', async (_req: Request, res: Response) => {
    try {
      const config = store.get();
      const provider = getProvider(config.network);
      const height = await provider.getBlockNumber();
      res.json({ height });
    } catch (e) {
      res.status(500).json({ error: (e as Error).message });
    }
  });

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
  r.post('/encode', requireUser, async (req: Request, res: Response) => {
    const { method, params, paramTypes } = req.body as {
      method: string;
      params: string[];
      paramTypes: Array<'address' | 'u256' | 'bytes'>;
    };

    // Validate inputs
    if (!method || typeof method !== 'string') {
      res.status(400).json({ error: 'method must be a non-empty string' });
      return;
    }
    if (!Array.isArray(params)) {
      res.status(400).json({ error: 'params must be an array' });
      return;
    }
    if (!Array.isArray(paramTypes) || paramTypes.length !== params.length) {
      res.status(400).json({ error: 'paramTypes must be an array of same length as params' });
      return;
    }
    const validParamTypes = ['address', 'u256', 'bytes'];
    for (const pt of paramTypes) {
      if (!validParamTypes.includes(pt)) {
        res.status(400).json({ error: `invalid paramType '${pt}', must be one of: ${validParamTypes.join(', ')}` });
        return;
      }
    }

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
  r.post('/simulate', requireUser, async (req: Request, res: Response) => {
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
      const contractAbi = resolveAbi(abi);

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

  /** POST /api/tx/read — read a value from a contract */
  r.post('/read', async (req: Request, res: Response) => {
    const { contract: contractAddr, method, abi, params: rawParams } = req.body as {
      contract: string;
      method: string;
      abi?: unknown;
      params?: unknown[];
    };
    try {
      const config = store.get();
      const provider = getProvider(config.network);
      const network = getNetwork(config.network);
      const contractAbi = resolveAbi(abi);
      const contract = getContract(contractAddr, contractAbi as typeof OP_20_ABI, provider, network);
      type ContractFnMap = Record<string, (...args: unknown[]) => Promise<{ properties: Record<string, unknown> }>>;
      const c = contract as unknown as ContractFnMap;
      if (!c[method]) {
        res.status(400).json({ error: `Method "${method}" not found on contract` });
        return;
      }
      // Convert params if provided (for parameterized reads like balanceOf)
      const callParams = (rawParams ?? []).map(val => {
        const s = String(val);
        // Detect address (0x + 64 hex) and wrap it
        if (/^0x[0-9a-fA-F]{64}$/.test(s)) return Address.wrap(Buffer.from(s.replace(/^0x/, ''), 'hex'));
        // Try as BigInt for numeric types
        try { return BigInt(s); } catch { return val; }
      });
      const result = await c[method]!(...callParams);
      res.json({ result: result.properties });
    } catch (e) {
      res.status(500).json({ error: (e as Error).message });
    }
  });

  /** POST /api/tx/sighash — build OPNet tx with dummy sigs, extract per-input sighashes for FROST ceremony */
  r.post('/sighash', requireUser, async (req: Request, res: Response) => {
    const { contract: contractAddr, method, params: rawParams, paramTypes, abi, signature } = req.body as {
      contract: string;
      method: string;
      params: unknown[];
      paramTypes?: Array<'address' | 'u256' | 'bytes'>;
      abi?: unknown;
      signature: string;
    };

    if (!signature || !/^[0-9a-fA-F]+$/.test(signature)) {
      res.status(400).json({ error: 'invalid signature hex' });
      return;
    }

    const params = (rawParams ?? []).map((val, i) => {
      const t = paramTypes?.[i];
      const s = String(val);
      if (t === 'address') return Address.wrap(Buffer.from(s.replace(/^0[xX]/, ''), 'hex'));
      if (t === 'u256') return BigInt(s);
      return val;
    });

    try {
      const config = store.get();
      if (!config.wallet) { res.status(400).json({ error: 'No wallet configured' }); return; }
      if (!config.permafrost) { res.status(400).json({ error: 'No DKG ceremony completed' }); return; }
      if (!config.permafrost.frostAggregateKey || !config.permafrost.frostUntweakedAggregateKey) {
        res.status(400).json({ error: 'No FROST keys configured — run DKG with V3 share files' });
        return;
      }

      const provider = getProvider(config.network);
      const network = getNetwork(config.network);
      const contractAbi = resolveAbi(abi);
      const { wallet, mnemonic } = generateWallet(config.wallet.mnemonic, config.network);

      const btcTweakedPubKey = config.permafrost.frostAggregateKey;
      const vaultAddr = Address.fromString(config.permafrost.combinedPubKey, btcTweakedPubKey);
      const refundAddress = config.permafrost.frostP2tr || config.wallet.p2tr;
      const contract = getContract(contractAddr, contractAbi as never, provider, network, vaultAddr);
      const fn = (contract as unknown as Record<string, unknown>)[method];
      if (typeof fn !== 'function') {
        mnemonic.zeroize(); wallet.zeroize();
        res.status(400).json({ error: `Method '${method}' not found` });
        return;
      }

      const callResult = await (fn as (...args: unknown[]) => Promise<{
        revert?: string;
        sendTransaction: (params: unknown) => Promise<{ transactionId: string; estimatedFees?: bigint }>;
      }>).call(contract, ...(params ?? []));

      if (callResult.revert) {
        mnemonic.zeroize(); wallet.zeroize();
        res.status(400).json({ error: `Simulation reverted: ${callResult.revert}` });
        return;
      }

      const challenge = await provider.getChallenge();
      const sigBytes = Buffer.from(signature, 'hex');
      const pubKeyBytes = Buffer.from(config.permafrost.combinedPubKey, 'hex');
      const thresholdSigner = new ThresholdMLDSASigner(sigBytes, pubKeyBytes);

      const tweakedPubKey = Buffer.from(config.permafrost.frostAggregateKey, 'hex');
      const untweakedPubKey = Buffer.from(config.permafrost.frostUntweakedAggregateKey, 'hex');
      const internalXOnly = toXOnly(untweakedPubKey as never);

      // Capture signer: extracts sighashes via dummy sigs. sendTransaction
      // will fail at finalization — we catch it and return the sighashes.
      const { signer: captureSigner, sighashes: capturedSighashes } =
        FrostPsbtSigner.createCapture(tweakedPubKey, internalXOnly, untweakedPubKey);

      const hybridSigner = wallet.keypair as typeof wallet.keypair & {
        multiSignPsbt: typeof captureSigner.multiSignPsbt;
      };
      (hybridSigner as unknown as Record<string, unknown>).multiSignPsbt =
        captureSigner.multiSignPsbt.bind(captureSigner);
      Object.defineProperty(hybridSigner, 'publicKey', {
        value: untweakedPubKey,
        configurable: true,
      });

      // Build tx with dummy sigs — will fail at finalization, that's expected
      try {
        await callResult.sendTransaction({
          signer: hybridSigner as never,
          mldsaSigner: thresholdSigner,
          refundTo: refundAddress,
          network,
          feeRate: TX_FEE_RATE,
          priorityFee: TX_PRIORITY_FEE,
          maximumAllowedSatToSpend: TX_MAX_SAT_SPEND,
          challenge,
        });
      } catch {
        // Expected: finalization fails with dummy sigs
      }

      mnemonic.zeroize();
      wallet.zeroize();

      if (capturedSighashes.length === 0) {
        res.status(500).json({ error: 'No sighashes captured — sendTransaction may have failed before signing' });
        return;
      }

      const sighashesHex = capturedSighashes.map(h => ({
        index: h.index,
        hash: Buffer.from(h.hash).toString('hex'),
        type: h.type,
      }));

      res.json({ sighashes: sighashesHex, challenge: JSON.stringify(challenge) });
    } catch (e) {
      res.status(500).json({ error: (e as Error).message });
    }
  });

  /** POST /api/tx/broadcast — build tx with ML-DSA sig and broadcast */
  r.post('/broadcast', requireUser, async (req: Request, res: Response) => {
    // FROST path: rebuild transaction with precomputed FROST sigs (matched by hash)
    const { frostSignatures } = req.body as {
      frostSignatures?: Array<{ hash: string; signature: string }>;
    };

    if (frostSignatures) {
      const { contract: contractAddr, method, params: rawParams, paramTypes, abi, signature, messageHash, challenge: challengeJson } = req.body as {
        contract: string; method: string; params: unknown[];
        paramTypes?: Array<'address' | 'u256' | 'bytes'>; abi?: unknown;
        signature: string; messageHash?: string; challenge?: string;
      };

      if (!signature || !/^[0-9a-fA-F]+$/.test(signature)) {
        res.status(400).json({ error: 'invalid ML-DSA signature hex' });
        return;
      }

      // Prevent double-broadcast
      if (messageHash) {
        const cached = broadcastResults.get(messageHash);
        if (cached?.transactionId) {
          res.json({ success: true, alreadyBroadcast: true, ...cached });
          return;
        }
        broadcastResults.set(messageHash, { _ts: Date.now() });
      }

      // Build sig-by-hash map
      const sigsByHash = new Map<string, Uint8Array>();
      for (const fs of frostSignatures) {
        if (typeof fs.signature !== 'string' || !/^[0-9a-fA-F]{128}$/.test(fs.signature)) {
          res.status(400).json({ error: `Invalid FROST signature for hash ${fs.hash?.slice(0, 16)}` });
          return;
        }
        sigsByHash.set(fs.hash, Buffer.from(fs.signature, 'hex'));
      }

      const params = (rawParams ?? []).map((val, i) => {
        const t = paramTypes?.[i];
        const s = String(val);
        if (t === 'address') return Address.wrap(Buffer.from(s.replace(/^0[xX]/, ''), 'hex'));
        if (t === 'u256') return BigInt(s);
        return val;
      });

      try {
        const config = store.get();
        if (!config.wallet || !config.permafrost?.frostAggregateKey || !config.permafrost?.frostUntweakedAggregateKey) {
          res.status(400).json({ error: 'Wallet or FROST keys not configured' });
          return;
        }

        const provider = getProvider(config.network);
        const network = getNetwork(config.network);
        const contractAbi = resolveAbi(abi);
        const { wallet, mnemonic } = generateWallet(config.wallet.mnemonic, config.network);

        const vaultAddr = Address.fromString(config.permafrost.combinedPubKey, config.permafrost.frostAggregateKey);
        const refundAddress = config.permafrost.frostP2tr || config.wallet.p2tr;
        const contract = getContract(contractAddr, contractAbi as never, provider, network, vaultAddr);
        const fn = (contract as unknown as Record<string, unknown>)[method];
        if (typeof fn !== 'function') {
          mnemonic.zeroize(); wallet.zeroize();
          res.status(400).json({ error: `Method '${method}' not found` });
          return;
        }

        const callResult = await (fn as (...args: unknown[]) => Promise<{
          revert?: string;
          sendTransaction: (params: unknown) => Promise<{ transactionId: string; estimatedFees?: bigint }>;
        }>).call(contract, ...(params ?? []));

        if (callResult.revert) {
          mnemonic.zeroize(); wallet.zeroize();
          if (messageHash) broadcastResults.delete(messageHash);
          res.status(400).json({ error: `Simulation reverted: ${callResult.revert}` });
          return;
        }

        // Reuse the challenge from the sighash endpoint to ensure identical tx build
        const challenge = challengeJson ? JSON.parse(challengeJson) : await provider.getChallenge();
        const sigBytes = Buffer.from(signature, 'hex');
        const pubKeyBytes = Buffer.from(config.permafrost.combinedPubKey, 'hex');
        const thresholdSigner = new ThresholdMLDSASigner(sigBytes, pubKeyBytes);

        const tweakedPubKey = Buffer.from(config.permafrost.frostAggregateKey, 'hex');
        const untweakedPubKey = Buffer.from(config.permafrost.frostUntweakedAggregateKey, 'hex');
        const internalXOnly = toXOnly(untweakedPubKey as never);

        // Replay signer: applies precomputed FROST sigs matched by sighash
        const replaySigner = FrostPsbtSigner.createReplay(tweakedPubKey, internalXOnly, untweakedPubKey, sigsByHash);

        const hybridSigner = wallet.keypair as typeof wallet.keypair & {
          multiSignPsbt: typeof replaySigner.multiSignPsbt;
        };
        (hybridSigner as unknown as Record<string, unknown>).multiSignPsbt =
          replaySigner.multiSignPsbt.bind(replaySigner);
        Object.defineProperty(hybridSigner, 'publicKey', {
          value: untweakedPubKey,
          configurable: true,
        });

        const receipt = await callResult.sendTransaction({
          signer: hybridSigner as never,
          mldsaSigner: thresholdSigner,
          refundTo: refundAddress,
          network,
          feeRate: TX_FEE_RATE,
          priorityFee: TX_PRIORITY_FEE,
          maximumAllowedSatToSpend: TX_MAX_SAT_SPEND,
          challenge,
        });

        mnemonic.zeroize();
        wallet.zeroize();

        const result = {
          transactionId: receipt.transactionId,
          estimatedFees: receipt.estimatedFees?.toString(),
        };
        if (messageHash) broadcastResults.set(messageHash, { ...result, _ts: Date.now() });
        res.json({ success: true, ...result });
      } catch (e) {
        const msg = e instanceof Error ? e.message : String(e);
        console.error('[broadcast/frost] error:', msg, e);
        if (messageHash) broadcastResults.delete(messageHash);
        res.status(500).json({ error: msg || 'FROST broadcast failed' });
      }
      return;
    }

    // Legacy path: single-keypair BTC signing
    const { contract: contractAddr, method, params: rawParams, paramTypes, abi, signature, messageHash } = req.body as {
      contract: string;
      method: string;
      params: unknown[];
      paramTypes?: Array<'address' | 'u256' | 'bytes'>;
      abi?: unknown;
      signature: string;
      messageHash?: string;
    };

    if (!signature || !/^[0-9a-fA-F]+$/.test(signature)) {
      res.status(400).json({ error: 'invalid signature hex' });
      return;
    }

    // Prevent double-broadcast
    if (messageHash) {
      const cached = broadcastResults.get(messageHash);
      if (cached) {
        res.json({ success: !!cached.transactionId, alreadyBroadcast: true, ...cached });
        return;
      }
      // Lock immediately to block concurrent requests
      broadcastResults.set(messageHash, { _ts: Date.now() });
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
      const contractAbi = resolveAbi(abi);

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

      // FROST spike: wrap the wallet's keypair in a FrostPsbtSigner to exercise
      // the SDK's multiSignPsbt (wallet-based) code path instead of the
      // non-wallet path that demands a raw private key for Taproot tweaking.
      const internalXOnly = toXOnly(wallet.keypair.publicKey);
      const tweak = tapTweakHash(internalXOnly, undefined);
      const tweakedKeypair = wallet.keypair.tweak(tweak);
      const frostSigner = new FrostPsbtSigner(
        (hash: Uint8Array) => tweakedKeypair.signSchnorr!(hash as never),
        tweakedKeypair.publicKey,
        internalXOnly,
      );

      // Send transaction
      const receipt = await callResult.sendTransaction({
        signer: frostSigner as never,
        mldsaSigner: thresholdSigner,
        refundTo: config.wallet.p2tr,
        network,
        feeRate: TX_FEE_RATE,
        priorityFee: TX_PRIORITY_FEE,
        maximumAllowedSatToSpend: TX_MAX_SAT_SPEND,
        challenge,
      });

      mnemonic.zeroize();
      wallet.zeroize();

      const result = {
        transactionId: receipt.transactionId,
        estimatedFees: receipt.estimatedFees?.toString(),
      };
      if (messageHash) broadcastResults.set(messageHash, { ...result, _ts: Date.now() });

      res.json({ success: true, ...result });
    } catch (e) {
      const msg = e instanceof Error ? e.message : typeof e === 'string' ? e : JSON.stringify(e);
      console.error('[broadcast] error:', msg, e);
      // On error, clear the lock so it can be retried
      if (messageHash) broadcastResults.delete(messageHash);
      res.status(500).json({ error: msg || 'Broadcast failed (unknown error)' });
    }
  });

  return r;
}
