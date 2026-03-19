import { Router, type Request, type Response } from 'express';
import {
  createChallenge, consumeChallenge,
  verifyMLDSA, createToken, getTokenInfo,
} from '../lib/auth.js';
import type { UserStore } from '../lib/users.js';

const BASE64_RE = /^[A-Za-z0-9+/]+=*$/;

function decodeBase64(str: string): Uint8Array | null {
  if (!str || !BASE64_RE.test(str)) return null;
  const buf = Buffer.from(str, 'base64');
  return buf.length > 0 ? new Uint8Array(buf) : null;
}

export function authRoutes(userStore: UserStore): Router {
  const r = Router();

  /** GET /api/auth/challenge — generate one-use challenge */
  r.get('/challenge', (_req: Request, res: Response) => {
    const challenge = createChallenge();
    res.json({ challenge });
  });

  /** POST /api/auth/verify — verify ML-DSA sig, return token + role */
  r.post('/verify', (req: Request, res: Response) => {
    const { challenge, signature, publicKey, sessionCode } = req.body as {
      challenge?: string;
      signature?: string;  // base64-encoded ML-DSA sig
      publicKey?: string;  // base64-encoded ML-DSA pubkey (NOT tweakedPubKey)
      sessionCode?: string; // DKG session code — auto-registers as user if provided
    };

    if (!challenge || !signature || !publicKey) {
      res.status(400).json({ error: 'challenge, signature, and publicKey required' });
      return;
    }

    if (!consumeChallenge(challenge)) {
      res.status(400).json({ error: 'Invalid or expired challenge' });
      return;
    }

    const sigBytes = decodeBase64(signature);
    const pubKeyBytes = decodeBase64(publicKey);
    if (!sigBytes) { res.status(400).json({ error: 'Invalid base64 in signature' }); return; }
    if (!pubKeyBytes) { res.status(400).json({ error: 'Invalid base64 in publicKey' }); return; }

    const result = verifyMLDSA(sigBytes, pubKeyBytes, challenge);
    if (!result.valid || !result.walletAddress) {
      res.status(401).json({ error: result.error || 'Verification failed' });
      return;
    }

    let user = userStore.getUser(result.walletAddress);

    // Auto-register as user if a DKG session code is provided
    if (!user && sessionCode?.trim()) {
      try {
        user = userStore.addUser(result.walletAddress, 'user', result.walletAddress.slice(0, 10));
      } catch {
        // Already exists (race condition) — try fetching again
        user = userStore.getUser(result.walletAddress);
      }
    }

    if (!user) {
      res.json({ authenticated: false, needsInvite: true, address: result.walletAddress });
      return;
    }

    const token = createToken(user.role, user.address);
    res.json({ authenticated: true, token, role: user.role, address: user.address, label: user.label });
  });

  /** POST /api/auth/redeem — verify sig + use invite code to register */
  r.post('/redeem', (req: Request, res: Response) => {
    const { challenge, signature, publicKey, inviteCode, label } = req.body as {
      challenge?: string;
      signature?: string;
      publicKey?: string;
      inviteCode?: string;
      label?: string;
    };

    if (!challenge || !signature || !publicKey || !inviteCode) {
      res.status(400).json({ error: 'challenge, signature, publicKey, and inviteCode required' });
      return;
    }

    if (!consumeChallenge(challenge)) {
      res.status(400).json({ error: 'Invalid or expired challenge' });
      return;
    }

    const sigBytes = decodeBase64(signature);
    const pubKeyBytes = decodeBase64(publicKey);
    if (!sigBytes || !pubKeyBytes) {
      res.status(400).json({ error: 'Invalid base64 encoding' });
      return;
    }

    const result = verifyMLDSA(sigBytes, pubKeyBytes, challenge);
    if (!result.valid || !result.walletAddress) {
      res.status(401).json({ error: result.error || 'Verification failed' });
      return;
    }

    const user = userStore.redeemInvite(inviteCode, result.walletAddress, label || result.walletAddress.slice(0, 10));
    if (!user) {
      res.status(400).json({ error: 'Invalid, expired, or exhausted invite code' });
      return;
    }

    const token = createToken(user.role, user.address);
    res.json({ authenticated: true, token, role: user.role, address: user.address, label: user.label });
  });

  /** GET /api/auth/me — return current session info */
  r.get('/me', (req: Request, res: Response) => {
    const auth = req.headers.authorization;
    if (!auth?.startsWith('Bearer ')) {
      res.json({ authenticated: false });
      return;
    }
    const info = getTokenInfo(auth.slice(7));
    if (!info) {
      res.json({ authenticated: false });
      return;
    }
    res.json({ authenticated: true, role: info.role, address: info.address });
  });

  return r;
}
