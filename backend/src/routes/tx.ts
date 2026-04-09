import { Router, type Request, type Response, type RequestHandler } from 'express';
import { createHash, randomBytes } from 'node:crypto';
import { Address, BinaryWriter } from '@btc-vision/transaction';
import { Transaction, toXOnly, tapTweakHash } from '@btc-vision/bitcoin';
import { getContract, OP_20_ABI } from 'opnet';
import { ConfigStore } from '../lib/config-store.js';
import { getProvider, getNetwork, generateWallet } from '../lib/opnet-client.js';
import { ThresholdMLDSASigner } from '../lib/threshold-signer.js';
import { FrostPsbtSigner } from '../lib/frost-psbt-signer.js';
import { computeKeyLinkHash, withFrostLegacySig } from '../lib/frost-link.js';

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

  // Cached capture data for FROST template-tx flow (5 min TTL)
  // Stores finalized template transactions (with dummy sigs) + sighash→input mapping
  interface CachedCapture {
    templateTxs: string[];  // raw tx hex [funding, interaction]
    sighashMap: Map<string, { txIndex: number; inputIndex: number; type: 'script-path' | 'key-path' }>;
    ts: number;
  }
  const captureCache = new Map<string, CachedCapture>();
  setInterval(() => {
    const cutoff = Date.now() - 5 * 60 * 1000;
    for (const [k, v] of captureCache) { if (v.ts < cutoff) captureCache.delete(k); }
  }, 60 * 1000);

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

  /** POST /api/tx/sighash — build OPNet tx with dummy sigs, capture template txs + sighashes for FROST ceremony */
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

      const sigBytes = Buffer.from(signature, 'hex');
      const pubKeyBytes = Buffer.from(config.permafrost.combinedPubKey, 'hex');
      const thresholdSigner = new ThresholdMLDSASigner(sigBytes, pubKeyBytes);

      const tweakedPubKey = Buffer.from(config.permafrost.frostAggregateKey, 'hex');
      const untweakedPubKey = Buffer.from(config.permafrost.frostUntweakedAggregateKey, 'hex');
      const internalXOnly = toXOnly(untweakedPubKey as never);

      // Capture signer: extracts sighashes via dummy sigs, tracks per-call data
      const { signer: captureSigner, calls: capturedCalls } =
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

      // Intercept provider broadcast to capture finalized template txs
      const capturedTemplateTxs: string[] = [];
      const origSendRawPkg = (provider as unknown as Record<string, unknown>).sendRawTransactionPackage as (...args: unknown[]) => Promise<unknown>;
      const origSendRaw = (provider as unknown as Record<string, unknown>).sendRawTransaction as (...args: unknown[]) => Promise<unknown>;
      (provider as unknown as Record<string, unknown>).sendRawTransactionPackage = async (txs: string[]) => {
        capturedTemplateTxs.push(...txs);
        throw new Error('__capture_only__');
      };
      (provider as unknown as Record<string, unknown>).sendRawTransaction = async (tx: string) => {
        capturedTemplateTxs.push(tx);
        throw new Error('__capture_only__');
      };

      // Build tx with dummy sigs — SDK finalizes (dummy sigs pass finalization),
      // then tries to broadcast → our override captures the hex and throws.
      // If FROST legacy sig exists, inject it so the SDK produces valid key-link signatures.
      const frostLegacySigHex = config.permafrost?.frostLegacySig;
      const sendTxParams = {
        signer: hybridSigner as never,
        mldsaSigner: thresholdSigner,
        refundTo: refundAddress,
        network,
        feeRate: TX_FEE_RATE,
        priorityFee: TX_PRIORITY_FEE,
        maximumAllowedSatToSpend: TX_MAX_SAT_SPEND,
      };

      try {
        if (frostLegacySigHex) {
          const keyLinkHash = computeKeyLinkHash(pubKeyBytes, tweakedPubKey, untweakedPubKey, config.network);
          const frostLegacySigBytes = Buffer.from(frostLegacySigHex, 'hex');
          await withFrostLegacySig(
            keyLinkHash, frostLegacySigBytes, tweakedPubKey,
            hybridSigner as unknown as { tweak?: (...args: unknown[]) => unknown },
            () => callResult.sendTransaction(sendTxParams),
          );
        } else {
          await callResult.sendTransaction(sendTxParams);
        }
      } catch {
        // Expected: our __capture_only__ throw prevents actual broadcast
      }

      // Restore provider methods
      (provider as unknown as Record<string, unknown>).sendRawTransactionPackage = origSendRawPkg;
      (provider as unknown as Record<string, unknown>).sendRawTransaction = origSendRaw;

      mnemonic.zeroize();
      wallet.zeroize();

      if (capturedTemplateTxs.length === 0 || capturedCalls.length < capturedTemplateTxs.length) {
        res.status(500).json({ error: 'Capture failed — no template transactions or insufficient signing rounds' });
        return;
      }

      // The last N multiSignPsbt calls correspond to the N template txs.
      // signInteraction order: ...fee-estimation..., final-funding, final-interaction
      // sendRawTransactionPackage order: [funding, interaction]
      const numTxs = capturedTemplateTxs.length;
      const finalCalls = capturedCalls.slice(-numTxs);

      // Build sighash → (txIndex, inputIndex, type) map for the final builds only
      const sighashMap = new Map<string, { txIndex: number; inputIndex: number; type: 'script-path' | 'key-path' }>();
      const finalSighashes: Array<{ index: number; hash: string; type: string }> = [];
      let idx = 0;
      for (let txIdx = 0; txIdx < finalCalls.length; txIdx++) {
        for (const sh of finalCalls[txIdx]!.sighashes) {
          const hashHex = Buffer.from(sh.hash).toString('hex');
          sighashMap.set(hashHex, { txIndex: txIdx, inputIndex: sh.inputIndex, type: sh.type });
          finalSighashes.push({ index: idx++, hash: hashHex, type: sh.type });
        }
      }

      if (finalSighashes.length === 0) {
        res.status(500).json({ error: 'No sighashes captured from final transaction builds' });
        return;
      }

      const captureToken = randomBytes(16).toString('hex');
      captureCache.set(captureToken, { templateTxs: capturedTemplateTxs, sighashMap, ts: Date.now() });
      res.json({ sighashes: finalSighashes, challengeToken: captureToken });
    } catch (e) {
      res.status(500).json({ error: (e as Error).message });
    }
  });

  /** POST /api/tx/broadcast — broadcast with FROST sigs or legacy single-key */
  r.post('/broadcast', requireUser, async (req: Request, res: Response) => {
    // FROST path: replace dummy sigs in cached template txs with real FROST sigs
    const { frostSignatures } = req.body as {
      frostSignatures?: Array<{ hash: string; signature: string }>;
    };

    if (frostSignatures) {
      const { messageHash, challengeToken } = req.body as {
        messageHash?: string; challengeToken?: string;
      };

      // Prevent double-broadcast
      if (messageHash) {
        const cached = broadcastResults.get(messageHash);
        if (cached?.transactionId) {
          res.json({ success: true, alreadyBroadcast: true, ...cached });
          return;
        }
        broadcastResults.set(messageHash, { _ts: Date.now() });
      }

      if (!challengeToken) {
        res.status(400).json({ error: 'challengeToken is required for FROST broadcast' });
        return;
      }

      const capture = captureCache.get(challengeToken);
      if (!capture) {
        res.status(400).json({ error: 'Capture session expired or not found — run sighash again' });
        return;
      }

      // Validate FROST signatures
      const sigsByHash = new Map<string, Uint8Array>();
      for (const fs of frostSignatures) {
        if (typeof fs.signature !== 'string' || !/^[0-9a-fA-F]{128}$/.test(fs.signature)) {
          if (messageHash) broadcastResults.delete(messageHash);
          res.status(400).json({ error: `Invalid FROST signature for hash ${fs.hash?.slice(0, 16)}` });
          return;
        }
        sigsByHash.set(fs.hash, Buffer.from(fs.signature, 'hex'));
      }

      try {
        // Replace dummy sigs in template transactions with real FROST sigs
        const modifiedTxs: string[] = [];
        for (let txIdx = 0; txIdx < capture.templateTxs.length; txIdx++) {
          const tx = Transaction.fromHex(capture.templateTxs[txIdx]!);

          // Find all sighashes that belong to this template tx
          for (const [hashHex, mapping] of capture.sighashMap) {
            if (mapping.txIndex !== txIdx) continue;

            const frostSig = sigsByHash.get(hashHex);
            if (!frostSig) {
              throw new Error(`Missing FROST signature for sighash ${hashHex.slice(0, 16)}...`);
            }

            const input = tx.ins[mapping.inputIndex];
            if (!input) {
              throw new Error(`Template tx ${txIdx} has no input at index ${mapping.inputIndex}`);
            }

            if (mapping.type === 'script-path') {
              // Witness: [contractSecret, scriptSignerSig, mainSignerSig(dummy), script, controlBlock]
              // Replace witness[2] (the dummy main signer sig)
              if (input.witness.length < 5) {
                throw new Error(`Unexpected witness length ${input.witness.length} for script-path input ${mapping.inputIndex}`);
              }
              input.witness[2] = frostSig;
            } else {
              // Key-path witness: [tapKeySig(dummy)]
              // Replace witness[0]
              if (input.witness.length < 1) {
                throw new Error(`Empty witness for key-path input ${mapping.inputIndex}`);
              }
              input.witness[0] = frostSig;
            }

            console.log(`[frost-broadcast] tx${txIdx} input ${mapping.inputIndex} (${mapping.type}): sig replaced`);
          }

          modifiedTxs.push(tx.toHex());
        }

        // Broadcast via provider
        const config = store.get();
        const provider = getProvider(config.network);

        let transactionId: string;
        if (modifiedTxs.length >= 2) {
          const pkgResult = await provider.sendRawTransactionPackage(modifiedTxs, true);
          if (!pkgResult.success) {
            throw new Error(`Package broadcast failed: ${pkgResult.error || 'unknown'}`);
          }
          // Interaction tx is the second in the package [funding, interaction]
          const interactionResult = pkgResult.sequentialResults?.[1];
          if (interactionResult && !interactionResult.success) {
            throw new Error(`Interaction tx failed: ${interactionResult.error || 'unknown'}`);
          }
          transactionId = interactionResult?.txid || 'broadcast-ok';
        } else if (modifiedTxs.length === 1) {
          const txResult = await provider.sendRawTransaction(modifiedTxs[0]!, false);
          if (!txResult.success) {
            throw new Error(`Broadcast failed: ${txResult.error || 'unknown'}`);
          }
          transactionId = txResult.result || 'broadcast-ok';
        } else {
          throw new Error('No template transactions to broadcast');
        }

        // Clean up capture cache
        captureCache.delete(challengeToken);

        const result = { transactionId };
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
