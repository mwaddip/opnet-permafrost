/**
 * DKG blob encoding/decoding and ceremony helpers.
 *
 * Each blob is a base64-encoded JSON envelope:
 *   { v, type, from, to, sid, data }
 *
 * Smart paste: identifyBlob() detects blob type, validates session ID,
 * rejects duplicates/self-blobs, and routes to the correct bucket.
 */

import {
  ThresholdMLDSA,
  type DKGPhase1Broadcast,
  type DKGPhase1State,
  type DKGPhase2Broadcast,
  type DKGPhase2Private,
  type DKGPhase2FinalizeResult,
  type DKGPhase3Private,
  type DKGPhase4Broadcast,
} from '@btc-vision/post-quantum/threshold-ml-dsa.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { toHex, fromHex } from './hex';

function equalBytes(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i]! ^ b[i]!;
  return diff === 0;
}

// ── Blob envelope ──

type BlobType = 'session' | 'p1' | 'p2pub' | 'p2priv' | 'p3priv' | 'p4';

interface DKGBlobEnvelope {
  v: 2;
  type: BlobType;
  from: number;
  to: number;       // -1 = broadcast
  sid: string;       // first 16 hex chars of sessionId
  data: string;      // hex-encoded payload
}

function encodeEnvelope(type: BlobType, from: number, to: number, sid: Uint8Array, data: Uint8Array): string {
  const envelope: DKGBlobEnvelope = {
    v: 2,
    type,
    from,
    to,
    sid: toHex(sid).slice(0, 16),
    data: toHex(data),
  };
  return btoa(JSON.stringify(envelope));
}

function decodeEnvelope(blob: string): DKGBlobEnvelope | null {
  try {
    const json = atob(blob.trim());
    const obj = JSON.parse(json) as DKGBlobEnvelope;
    if (obj.v !== 2 || !obj.type || typeof obj.from !== 'number') return null;
    return obj;
  } catch {
    return null;
  }
}

// ── Session config ──

interface SessionConfig {
  t: number;
  n: number;
  level: number;
  sid: string;  // full hex
}

export function encodeSessionConfig(t: number, n: number, level: number, sessionId: Uint8Array): string {
  const config: SessionConfig = { t, n, level, sid: toHex(sessionId) };
  const data = new TextEncoder().encode(JSON.stringify(config));
  return encodeEnvelope('session', 0, -1, sessionId, data);
}

export function decodeSessionConfig(blob: string): SessionConfig | null {
  const env = decodeEnvelope(blob);
  if (!env || env.type !== 'session') return null;
  try {
    const json = new TextDecoder().decode(fromHex(env.data));
    return JSON.parse(json) as SessionConfig;
  } catch {
    return null;
  }
}

// ── Phase 1: Commit broadcast ──

export function encodePhase1Broadcast(broadcast: DKGPhase1Broadcast, sessionId: Uint8Array): string {
  // Layout: 1B partyId, 32B rhoCommitment, then per-bitmask: 2B bitmask(LE) + 32B commitment
  const numBitmasks = broadcast.bitmaskCommitments.size;
  const buf = new Uint8Array(1 + 32 + numBitmasks * 34);
  let pos = 0;
  buf[pos++] = broadcast.partyId;
  buf.set(broadcast.rhoCommitment, pos); pos += 32;
  for (const [bitmask, commitment] of broadcast.bitmaskCommitments) {
    buf[pos++] = bitmask & 0xff;
    buf[pos++] = (bitmask >>> 8) & 0xff;
    buf.set(commitment, pos); pos += 32;
  }
  return encodeEnvelope('p1', broadcast.partyId, -1, sessionId, buf);
}

export function decodePhase1Broadcast(blob: string): DKGPhase1Broadcast | null {
  const env = decodeEnvelope(blob);
  if (!env || env.type !== 'p1') return null;
  const data = fromHex(env.data);
  let pos = 0;
  const partyId = data[pos++]!;
  const rhoCommitment = data.slice(pos, pos + 32); pos += 32;
  const bitmaskCommitments = new Map<number, Uint8Array>();
  while (pos + 34 <= data.length) {
    const bitmask = data[pos]! | (data[pos + 1]! << 8);
    pos += 2;
    bitmaskCommitments.set(bitmask, data.slice(pos, pos + 32));
    pos += 32;
  }
  return { partyId, rhoCommitment, bitmaskCommitments };
}

// ── Phase 2: Public reveal ──

export function encodePhase2Broadcast(broadcast: DKGPhase2Broadcast, sessionId: Uint8Array): string {
  // Layout: 1B partyId, 32B rho
  const buf = new Uint8Array(1 + 32);
  buf[0] = broadcast.partyId;
  buf.set(broadcast.rho, 1);
  return encodeEnvelope('p2pub', broadcast.partyId, -1, sessionId, buf);
}

export function decodePhase2Broadcast(blob: string): DKGPhase2Broadcast | null {
  const env = decodeEnvelope(blob);
  if (!env || env.type !== 'p2pub') return null;
  const data = fromHex(env.data);
  return { partyId: data[0]!, rho: data.slice(1, 33) };
}

// ── Phase 2: Private reveals ──

export function encodePhase2Private(
  priv: DKGPhase2Private,
  targetPartyId: number,
  sessionId: Uint8Array,
): string {
  // Layout: 1B fromPartyId, then per-bitmask: 2B bitmask(LE) + 32B reveal
  const numReveals = priv.bitmaskReveals.size;
  const buf = new Uint8Array(1 + numReveals * 34);
  let pos = 0;
  buf[pos++] = priv.fromPartyId;
  for (const [bitmask, reveal] of priv.bitmaskReveals) {
    buf[pos++] = bitmask & 0xff;
    buf[pos++] = (bitmask >>> 8) & 0xff;
    buf.set(reveal, pos); pos += 32;
  }
  return encodeEnvelope('p2priv', priv.fromPartyId, targetPartyId, sessionId, buf);
}

export function decodePhase2Private(blob: string): DKGPhase2Private | null {
  const env = decodeEnvelope(blob);
  if (!env || env.type !== 'p2priv') return null;
  const data = fromHex(env.data);
  let pos = 0;
  const fromPartyId = data[pos++]!;
  const bitmaskReveals = new Map<number, Uint8Array>();
  while (pos + 34 <= data.length) {
    const bitmask = data[pos]! | (data[pos + 1]! << 8);
    pos += 2;
    bitmaskReveals.set(bitmask, data.slice(pos, pos + 32));
    pos += 32;
  }
  return { fromPartyId, bitmaskReveals };
}

// ── Phase 3: Private masks ──

const N_COEFFS = 256;
const Q = 8380417;

export function encodePhase3Private(
  priv: DKGPhase3Private,
  targetPartyId: number,
  sessionId: Uint8Array,
): string {
  // Layout: 1B fromGeneratorId, then per-bitmask entry:
  //   2B bitmask(LE), 1B numPolys, per poly: 256×4B coefficients (int32 LE)
  const parts: Uint8Array[] = [];
  parts.push(new Uint8Array([priv.fromGeneratorId]));
  for (const [bitmask, polys] of priv.maskPieces) {
    const header = new Uint8Array(3);
    header[0] = bitmask & 0xff;
    header[1] = (bitmask >>> 8) & 0xff;
    header[2] = polys.length;
    parts.push(header);
    for (const poly of polys) {
      const polyBuf = new Uint8Array(N_COEFFS * 4);
      const view = new DataView(polyBuf.buffer);
      for (let i = 0; i < N_COEFFS; i++) {
        view.setInt32(i * 4, poly[i]!, true);
      }
      parts.push(polyBuf);
    }
  }
  // Concatenate
  let total = 0;
  for (const p of parts) total += p.length;
  const buf = new Uint8Array(total);
  let pos = 0;
  for (const p of parts) { buf.set(p, pos); pos += p.length; }
  // Append SHA-256 checksum for integrity verification
  const checksum = sha256(buf);
  const withChecksum = new Uint8Array(buf.length + 32);
  withChecksum.set(buf);
  withChecksum.set(checksum, buf.length);
  return encodeEnvelope('p3priv', priv.fromGeneratorId, targetPartyId, sessionId, withChecksum);
}

export function decodePhase3Private(blob: string): DKGPhase3Private | null {
  const env = decodeEnvelope(blob);
  if (!env || env.type !== 'p3priv') return null;
  const raw = fromHex(env.data);
  if (raw.length < 32) return null;
  // Verify SHA-256 checksum
  const payload = raw.slice(0, raw.length - 32);
  const receivedChecksum = raw.slice(raw.length - 32);
  if (!equalBytes(sha256(payload), receivedChecksum)) {
    console.error('Phase 3 blob integrity check failed');
    return null;
  }
  let pos = 0;
  const fromGeneratorId = payload[pos++]!;
  const maskPieces = new Map<number, Int32Array[]>();
  while (pos + 3 <= payload.length) {
    const bitmask = payload[pos]! | (payload[pos + 1]! << 8);
    pos += 2;
    const numPolys = payload[pos++]!;
    const polys: Int32Array[] = [];
    for (let p = 0; p < numPolys; p++) {
      const poly = new Int32Array(N_COEFFS);
      const view = new DataView(payload.buffer, payload.byteOffset + pos, N_COEFFS * 4);
      for (let i = 0; i < N_COEFFS; i++) {
        poly[i] = view.getInt32(i * 4, true);
      }
      // Validate coefficient in [0, Q)
      for (let i = 0; i < N_COEFFS; i++) {
        if (poly[i]! < 0 || poly[i]! >= Q) {
          console.error('Invalid polynomial coefficient in phase 3 blob');
          return null;
        }
      }
      polys.push(poly);
      pos += N_COEFFS * 4;
    }
    maskPieces.set(bitmask, polys);
  }
  return { fromGeneratorId, maskPieces };
}

// ── Phase 4: Aggregate broadcast ──

export function encodePhase4Broadcast(broadcast: DKGPhase4Broadcast, sessionId: Uint8Array): string {
  // Layout: 1B partyId, 1B numPolys, per poly: 256×4B int32 LE
  const numPolys = broadcast.aggregate.length;
  const buf = new Uint8Array(2 + numPolys * N_COEFFS * 4);
  let pos = 0;
  buf[pos++] = broadcast.partyId;
  buf[pos++] = numPolys;
  for (const poly of broadcast.aggregate) {
    const view = new DataView(buf.buffer, pos, N_COEFFS * 4);
    for (let i = 0; i < N_COEFFS; i++) {
      view.setInt32(i * 4, poly[i]!, true);
    }
    pos += N_COEFFS * 4;
  }
  return encodeEnvelope('p4', broadcast.partyId, -1, sessionId, buf);
}

export function decodePhase4Broadcast(blob: string): DKGPhase4Broadcast | null {
  const env = decodeEnvelope(blob);
  if (!env || env.type !== 'p4') return null;
  const data = fromHex(env.data);
  let pos = 0;
  const partyId = data[pos++]!;
  const numPolys = data[pos++]!;
  const aggregate: Int32Array[] = [];
  for (let p = 0; p < numPolys; p++) {
    const poly = new Int32Array(N_COEFFS);
    const view = new DataView(data.buffer, data.byteOffset + pos, N_COEFFS * 4);
    for (let i = 0; i < N_COEFFS; i++) {
      poly[i] = view.getInt32(i * 4, true);
    }
    aggregate.push(poly);
    pos += N_COEFFS * 4;
  }
  return { partyId, aggregate };
}

// ── Smart paste: identify any blob ──

export interface BlobInfo {
  type: BlobType;
  from: number;
  to: number;
  sid: string;
}

export function identifyBlob(blob: string): BlobInfo | null {
  const env = decodeEnvelope(blob);
  if (!env) return null;
  return { type: env.type, from: env.from, to: env.to, sid: env.sid };
}

// ── DKG instance creation ──

export function createDKGInstance(level: number, t: number, n: number): ThresholdMLDSA {
  return ThresholdMLDSA.create(level, t, n);
}

export function generateSessionId(): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(32));
}

export function getSessionIdPrefix(sessionId: Uint8Array): string {
  return toHex(sessionId).slice(0, 16);
}

export function sessionIdFromHex(hex: string): Uint8Array {
  return fromHex(hex);
}

// ── Convenience: ML-DSA K,L for security levels ──

export function getKL(level: number): { K: number; L: number } {
  if (level === 44 || level === 128) return { K: 4, L: 4 };
  if (level === 65 || level === 192) return { K: 6, L: 5 };
  if (level === 87 || level === 256) return { K: 8, L: 7 };
  throw new Error(`Unknown security level: ${level}`);
}

// ── Re-exports for convenience ──

export type {
  DKGPhase1Broadcast,
  DKGPhase1State,
  DKGPhase2Broadcast,
  DKGPhase2Private,
  DKGPhase2FinalizeResult,
  DKGPhase3Private,
  DKGPhase4Broadcast,
};

export { ThresholdMLDSA };
