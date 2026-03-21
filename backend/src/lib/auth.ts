import { createHash, randomBytes, scryptSync, timingSafeEqual } from 'node:crypto';
import type { Request, Response, NextFunction, RequestHandler } from 'express';
import { ml_dsa44, ml_dsa65, ml_dsa87 } from '@btc-vision/post-quantum/ml-dsa.js';
import type { ConfigStore } from './config-store.js';
import type { UserStore } from './users.js';

// ── Password hashing (for password auth mode) ──

const SCRYPT_KEYLEN = 64;

export function hashPassword(password: string): string {
  const salt = randomBytes(16).toString('hex');
  const hash = scryptSync(password, salt, SCRYPT_KEYLEN).toString('hex');
  return `${salt}:${hash}`;
}

export function verifyPassword(password: string, stored: string): boolean {
  const [salt, hash] = stored.split(':');
  if (!salt || !hash) return false;
  const computed = scryptSync(password, salt, SCRYPT_KEYLEN).toString('hex');
  return timingSafeEqual(Buffer.from(hash), Buffer.from(computed));
}

// ── Token management ──

interface TokenInfo {
  expiresAt: number;
  role: 'admin' | 'user' | 'password-admin'; // password-admin = legacy password mode
  address?: string; // wallet address (only for wallet mode)
}

const tokens = new Map<string, TokenInfo>();
const TOKEN_EXPIRY = 6 * 60 * 60 * 1000; // 6 hours

export function createToken(role: TokenInfo['role'], address?: string): string {
  const token = randomBytes(32).toString('hex');
  tokens.set(token, { expiresAt: Date.now() + TOKEN_EXPIRY, role, address });
  return token;
}

export function getTokenInfo(token: string): TokenInfo | null {
  const info = tokens.get(token);
  if (!info) return null;
  if (Date.now() > info.expiresAt) {
    tokens.delete(token);
    return null;
  }
  return info;
}

// ── Challenge management ──

interface Challenge {
  value: string;
  expiresAt: number;
}

const challenges = new Map<string, Challenge>();
const CHALLENGE_EXPIRY = 60_000; // 60 seconds

export function createChallenge(): string {
  const value = randomBytes(32).toString('hex');
  challenges.set(value, { value, expiresAt: Date.now() + CHALLENGE_EXPIRY });
  return value;
}

export function consumeChallenge(value: string): boolean {
  const c = challenges.get(value);
  if (!c) return false;
  challenges.delete(value); // one-use
  return Date.now() <= c.expiresAt;
}

// ── ML-DSA verification ──
// CRITICAL: this uses mldsaPubKey (1312/1952/2592 bytes), NOT p2tr/tweakedPubKey

interface MLDSALevel {
  sigSize: number;
  verify: (sig: Uint8Array, msg: Uint8Array, publicKey: Uint8Array) => boolean;
  name: string;
}

const MLDSA_LEVELS: ReadonlyMap<number, MLDSALevel> = new Map([
  [1312, { sigSize: 2420, verify: (s, m, p) => ml_dsa44.verify(s, m, p), name: 'ML-DSA-44' }],
  [1952, { sigSize: 3309, verify: (s, m, p) => ml_dsa65.verify(s, m, p), name: 'ML-DSA-65' }],
  [2592, { sigSize: 4627, verify: (s, m, p) => ml_dsa87.verify(s, m, p), name: 'ML-DSA-87' }],
]);

export function verifyMLDSA(
  signature: Uint8Array,
  mldsaPubKey: Uint8Array,
  challenge: string,
): { valid: boolean; walletAddress?: string; error?: string } {
  const level = MLDSA_LEVELS.get(mldsaPubKey.length);
  if (!level) return { valid: false, error: `unrecognized ML-DSA public key size: ${mldsaPubKey.length}` };
  if (signature.length !== level.sigSize) {
    return { valid: false, error: `signature size ${signature.length} doesn't match ${level.name} (expected ${level.sigSize})` };
  }

  // Reconstruct double-hash per OPWallet convention:
  // signedData = SHA256(hex(SHA256("PERMAFROST auth {challenge}")))
  const message = `PERMAFROST auth ${challenge}`;
  const messageHash = createHash('sha256').update(message).digest();
  const walletInput = messageHash.toString('hex');
  const signedHash = createHash('sha256').update(walletInput).digest();

  let isValid: boolean;
  try {
    isValid = level.verify(
      new Uint8Array(signature),
      new Uint8Array(signedHash),
      new Uint8Array(mldsaPubKey),
    );
  } catch (err) {
    return { valid: false, error: `${level.name} verify error: ${err instanceof Error ? err.message : String(err)}` };
  }

  if (!isValid) return { valid: false, error: 'signature verification failed' };

  // Wallet address = 0x + hex(SHA256(mldsaPubKey)) — NOT tweakedPubKey
  const walletAddress = '0x' + createHash('sha256').update(mldsaPubKey).digest('hex');
  return { valid: true, walletAddress };
}

// ── Role-aware middleware ──

function extractToken(req: Request): string | null {
  const auth = req.headers.authorization;
  if (!auth?.startsWith('Bearer ')) return null;
  return auth.slice(7);
}

export interface AuthMiddleware {
  requireAdmin: RequestHandler;
  requireUser: RequestHandler;
  requireRead: RequestHandler;
}

export function createAuthMiddleware(store: ConfigStore, userStore: UserStore): AuthMiddleware {
  function getAuthMode(): 'password' | 'wallet' {
    try {
      return store.get().authMode || 'password';
    } catch {
      return 'password';
    }
  }

  function isConfigLoaded(): boolean {
    try { store.get(); return true; } catch { return false; }
  }

  const requireAdmin: RequestHandler = (req: Request, res: Response, next: NextFunction): void => {
    if (!isConfigLoaded()) { next(); return; }
    const mode = getAuthMode();

    if (mode === 'password') {
      // Legacy: check admin password token, skip if no password set
      try {
        const config = store.get();
        if (!config.adminPasswordHash) { next(); return; }
      } catch { next(); return; }

      const token = extractToken(req);
      if (!token) { res.status(401).json({ error: 'Admin authentication required' }); return; }
      const info = getTokenInfo(token);
      if (!info) { res.status(401).json({ error: 'Invalid or expired token' }); return; }
      if (info.role !== 'password-admin') { res.status(403).json({ error: 'Admin role required' }); return; }
      next();
      return;
    }

    // Wallet mode
    const token = extractToken(req);
    if (!token) { res.status(401).json({ error: 'Authentication required' }); return; }
    const info = getTokenInfo(token);
    if (!info) { res.status(401).json({ error: 'Invalid or expired token' }); return; }
    if (info.role !== 'admin') { res.status(403).json({ error: 'Admin role required' }); return; }
    next();
  };

  const requireUser: RequestHandler = (req: Request, res: Response, next: NextFunction): void => {
    if (!isConfigLoaded()) { next(); return; }
    const mode = getAuthMode();

    if (mode === 'password') {
      requireAdmin(req, res, next);
      return;
    }

    // Wallet mode: admin or user
    const token = extractToken(req);
    if (!token) { res.status(401).json({ error: 'Authentication required' }); return; }
    const info = getTokenInfo(token);
    if (!info) { res.status(401).json({ error: 'Invalid or expired token' }); return; }
    if (info.role !== 'admin' && info.role !== 'user') {
      res.status(403).json({ error: 'User or admin role required' });
      return;
    }
    next();
  };

  const requireRead: RequestHandler = (req: Request, res: Response, next: NextFunction): void => {
    if (!isConfigLoaded()) { next(); return; }
    const mode = getAuthMode();

    if (mode === 'password') { next(); return; }

    // Wallet mode: check everybodyCanRead setting
    if (userStore.getEverybodyCanRead()) { next(); return; }

    // Need at least a valid token (any role)
    const token = extractToken(req);
    if (!token) { res.status(401).json({ error: 'Authentication required' }); return; }
    const info = getTokenInfo(token);
    if (!info) { res.status(401).json({ error: 'Invalid or expired token' }); return; }
    next();
  };

  return { requireAdmin, requireUser, requireRead };
}

// ── Periodic cleanup of expired tokens and challenges ──

setInterval(() => {
  const now = Date.now();
  for (const [key, info] of tokens) {
    if (now > info.expiresAt) tokens.delete(key);
  }
  for (const [key, c] of challenges) {
    if (now > c.expiresAt) challenges.delete(key);
  }
}, 5 * 60 * 1000); // every 5 minutes
