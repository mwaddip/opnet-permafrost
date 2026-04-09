/**
 * PERMAFROST share file encryption and download.
 *
 * V2: Uses ThresholdMLDSA DKG. Each party produces their own
 * ThresholdKeyShare via the distributed key generation protocol.
 * Share serialization uses the binary format from serialize.ts.
 */

import { encrypt } from './crypto';
import { serializeKeyShare, serializeCombinedV3 } from './serialize';
import { toHex } from './hex';
import type { ThresholdKeyShare } from '@btc-vision/post-quantum/threshold-ml-dsa.js';
import type { KeyPackage as FrostKeyPackage } from 'frots';

export interface ShareFile {
  version: 2;
  publicKey: string;
  partyId: number;
  threshold: number;
  parties: number;
  level: number;
  encrypted: string;
}

export interface ShareFileV3 {
  version: 3;
  publicKey: string;        // ML-DSA combined pubkey hex
  frostPublicKey: string;   // FROST aggregate pubkey hex (33-byte SEC1)
  partyId: number;
  threshold: number;
  parties: number;
  level: number;
  encrypted: string;        // V3 combined blob (ML-DSA + FROST)
}

/**
 * Encrypt a ThresholdKeyShare and produce a downloadable ShareFile JSON (V2).
 */
export async function encryptShareV2(
  share: ThresholdKeyShare,
  publicKeyHex: string,
  threshold: number,
  parties: number,
  level: number,
  K: number,
  L: number,
  password: string,
): Promise<ShareFile> {
  const serialized = serializeKeyShare(share, K, L);
  const encrypted = await encrypt(serialized, password);
  return {
    version: 2,
    publicKey: publicKeyHex,
    partyId: share.id,
    threshold,
    parties,
    level,
    encrypted,
  };
}

/**
 * Encrypt ML-DSA + FROST shares into a single downloadable ShareFileV3.
 */
export async function encryptShareV3(
  mldsaShare: ThresholdKeyShare,
  frostKeyPackage: FrostKeyPackage,
  publicKeyHex: string,
  frostPublicKeyHex: string,
  threshold: number,
  parties: number,
  level: number,
  K: number,
  L: number,
  password: string,
): Promise<ShareFileV3> {
  const serialized = serializeCombinedV3(mldsaShare, frostKeyPackage, K, L);
  const encrypted = await encrypt(serialized, password);
  return {
    version: 3,
    publicKey: publicKeyHex,
    frostPublicKey: frostPublicKeyHex,
    partyId: mldsaShare.id,
    threshold,
    parties,
    level,
    encrypted,
  };
}

/**
 * Trigger a JSON file download in the browser.
 */
export function downloadShareFile(shareFile: ShareFile | ShareFileV3): void {
  const prefix = shareFile.publicKey.slice(0, 16);
  const filename = `permafrost-share-${shareFile.partyId}-${prefix}.json`;
  const blob = new Blob([JSON.stringify(shareFile, null, 2)], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}

export { toHex };
