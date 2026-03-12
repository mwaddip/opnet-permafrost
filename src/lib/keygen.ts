/**
 * PERMAFROST share file encryption and download.
 *
 * V2: Uses ThresholdMLDSA DKG. Each party produces their own
 * ThresholdKeyShare via the distributed key generation protocol.
 * Share serialization uses the binary format from serialize.ts.
 */

import { encrypt } from './crypto';
import { serializeKeyShare } from './serialize';
import type { ThresholdKeyShare } from '@btc-vision/post-quantum/threshold-ml-dsa.js';

export interface ShareFile {
  version: 2;
  publicKey: string;
  partyId: number;
  threshold: number;
  parties: number;
  level: number;
  encrypted: string;
}

function toHex(bytes: Uint8Array): string {
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
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
 * Trigger a JSON file download in the browser.
 */
export function downloadShareFile(shareFile: ShareFile): void {
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
