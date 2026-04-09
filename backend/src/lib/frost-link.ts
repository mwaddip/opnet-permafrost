import { createHash } from 'node:crypto';
import { getEccLib, toXOnly } from '@btc-vision/bitcoin';
import { BinaryWriter } from '@btc-vision/transaction';
import type { NetworkName } from './types.js';

// From @btc-vision/transaction/src/chain/ChainData.ts
const BITCOIN_PROTOCOL_ID = new Uint8Array([
  0xe7, 0x84, 0x99, 0x5a, 0x41, 0x2d, 0x77, 0x39, 0x88, 0xc4, 0xb8, 0xe3, 0x33, 0xd7, 0xb3, 0x9d,
  0xfb, 0x3c, 0xab, 0xf1, 0x18, 0xd0, 0xd6, 0x45, 0x41, 0x1a, 0x91, 0x6c, 0xa2, 0x40, 0x79, 0x39,
]);

const CHAIN_IDS: Record<string, Uint8Array> = {
  mainnet: new Uint8Array([
    0x00, 0x00, 0x00, 0x00, 0x00, 0x19, 0xd6, 0x68, 0x9c, 0x08, 0x5a, 0xe1, 0x65, 0x83,
    0x1e, 0x93, 0x4f, 0xf7, 0x63, 0xae, 0x46, 0xa2, 0xa6, 0xc1, 0x72, 0xb3, 0xf1, 0xb6,
    0x0a, 0x8c, 0xe2, 0x6f,
  ]),
  testnet: new Uint8Array([
    0x00, 0x00, 0x00, 0x00, 0x09, 0x33, 0xea, 0x01, 0xad, 0x0e, 0xe9, 0x84, 0x20, 0x97,
    0x79, 0xba, 0xae, 0xc3, 0xce, 0xd9, 0x0f, 0xa3, 0xf4, 0x08, 0x71, 0x95, 0x26, 0xf8,
    0xd7, 0x7f, 0x49, 0x43,
  ]),
};

/**
 * Compute the static key-link message hash that the OPNet SDK uses for
 * `generateLegacySignature()`. All values are fixed after DKG.
 *
 * Returns the SHA-256 hash — this is what the FROST ceremony must sign.
 */
export function computeKeyLinkHash(
  mldsaPubKey: Uint8Array,
  frostAggregateKey: Uint8Array,      // 33 bytes SEC1 compressed (tweaked)
  frostUntweakedKey: Uint8Array,      // 33 bytes SEC1 compressed
  networkName: NetworkName,
): Uint8Array {
  const chainId = CHAIN_IDS[networkName];
  if (!chainId) throw new Error(`No chain ID for network: ${networkName}`);

  const hashedPubKey = createHash('sha256').update(mldsaPubKey).digest();
  const tweakedXOnly = toXOnly(frostAggregateKey as never);

  const writer = new BinaryWriter();
  writer.writeU8(0x2C); // MLDSASecurityLevel.LEVEL2 = 44
  writer.writeBytes(hashedPubKey);
  writer.writeBytes(tweakedXOnly);
  writer.writeBytes(frostUntweakedKey);
  writer.writeBytes(BITCOIN_PROTOCOL_ID);
  writer.writeBytes(chainId);

  const message = writer.getBuffer();
  return createHash('sha256').update(message).digest();
}

/**
 * Wraps an async callback so that during its execution, the shared ECC
 * backend's `signSchnorr` is intercepted: if the hash matches the
 * pre-computed key-link hash, the stored FROST legacy signature is
 * returned instead of signing with the (wrong) wallet private key.
 *
 * Also patches `hybridSigner.tweak()` so the SDK's tweaked signer gets
 * the correct FROST public key (not derived from the wallet's private key).
 */
export async function withFrostLegacySig<T>(
  keyLinkHash: Uint8Array,
  frostLegacySig: Uint8Array,
  frostTweakedKey: Uint8Array,   // 33 bytes SEC1
  hybridSigner: { tweak?: (...args: unknown[]) => unknown },
  fn: () => T | Promise<T>,
): Promise<T> {
  const ecc = getEccLib();
  const origSignSchnorr = ecc.signSchnorr!;

  // 1. Override signSchnorr to return FROST sig for the key-link hash
  (ecc as unknown as Record<string, unknown>).signSchnorr = (hash: Uint8Array, privateKey: Uint8Array): Uint8Array => {
    if (hash.length === keyLinkHash.length && hash.every((b, i) => b === keyLinkHash[i]!)) {
      return frostLegacySig;
    }
    return origSignSchnorr(hash as never, privateKey as never);
  };

  // 2. Override tweak() to fix the tweaked signer's publicKey
  const origTweak = hybridSigner.tweak;
  if (origTweak) {
    hybridSigner.tweak = (...args: unknown[]) => {
      const tweaked = (origTweak as (...a: unknown[]) => Record<string, unknown>).apply(hybridSigner, args);
      Object.defineProperty(tweaked, 'publicKey', {
        value: frostTweakedKey,
        configurable: true,
      });
      // Ensure privateKey is truthy (MessageSigner.signMessage checks it)
      if (!tweaked.privateKey) {
        Object.defineProperty(tweaked, 'privateKey', {
          value: new Uint8Array(32),
          configurable: true,
        });
      }
      return tweaked;
    };
  }

  try {
    return await fn();
  } finally {
    (ecc as unknown as Record<string, unknown>).signSchnorr = origSignSchnorr;
    if (origTweak) hybridSigner.tweak = origTweak;
  }
}
