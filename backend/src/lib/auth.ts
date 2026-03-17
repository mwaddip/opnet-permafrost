import { scryptSync, randomBytes, timingSafeEqual } from 'node:crypto';
import type { Request, Response, NextFunction } from 'express';
import type { ConfigStore } from './config-store.js';

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

const tokens = new Map<string, number>();
const TOKEN_EXPIRY = 60 * 60 * 1000; // 1 hour

export function createToken(): string {
  const token = randomBytes(32).toString('hex');
  tokens.set(token, Date.now() + TOKEN_EXPIRY);
  return token;
}

export function validateToken(token: string): boolean {
  const expiry = tokens.get(token);
  if (!expiry) return false;
  if (Date.now() > expiry) {
    tokens.delete(token);
    return false;
  }
  return true;
}

// ── Middleware ──

export function createRequireAdmin(store: ConfigStore) {
  return function requireAdmin(req: Request, res: Response, next: NextFunction): void {
    // If no admin password is set, allow through (backward compat)
    try {
      const config = store.get();
      if (!config.adminPasswordHash) {
        next();
        return;
      }
    } catch {
      // Config not loaded — allow through (fresh/locked state)
      next();
      return;
    }

    const auth = req.headers.authorization;
    if (!auth?.startsWith('Bearer ')) {
      res.status(401).json({ error: 'Admin authentication required' });
      return;
    }
    const token = auth.slice(7);
    if (!validateToken(token)) {
      res.status(401).json({ error: 'Invalid or expired admin token' });
      return;
    }
    next();
  };
}
