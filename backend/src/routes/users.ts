import { Router, type Request, type Response, type RequestHandler } from 'express';
import type { UserStore, Role } from '../lib/users.js';

export function userRoutes(userStore: UserStore, requireAdmin: RequestHandler): Router {
  const r = Router();

  r.get('/', requireAdmin, (_req: Request, res: Response) => {
    res.json({ users: userStore.listUsers() });
  });

  r.post('/', requireAdmin, (req: Request, res: Response) => {
    const { address, role, label } = req.body as { address?: string; role?: Role; label?: string };
    if (!address || !role || !label) {
      res.status(400).json({ error: 'address, role, and label required' });
      return;
    }
    if (role !== 'admin' && role !== 'user') {
      res.status(400).json({ error: 'role must be "admin" or "user"' });
      return;
    }
    try {
      const user = userStore.addUser(address, role, label);
      res.json({ ok: true, user });
    } catch (e) {
      res.status(409).json({ error: (e as Error).message });
    }
  });

  r.delete('/:address', requireAdmin, (req: Request, res: Response) => {
    try {
      userStore.removeUser(req.params.address!);
      res.json({ ok: true });
    } catch (e) {
      res.status(404).json({ error: (e as Error).message });
    }
  });

  r.patch('/:address', requireAdmin, (req: Request, res: Response) => {
    const { role } = req.body as { role?: Role };
    if (!role || (role !== 'admin' && role !== 'user')) {
      res.status(400).json({ error: 'role must be "admin" or "user"' });
      return;
    }
    try {
      userStore.updateRole(req.params.address!, role);
      res.json({ ok: true });
    } catch (e) {
      res.status(404).json({ error: (e as Error).message });
    }
  });

  return r;
}

export function inviteRoutes(userStore: UserStore, requireAdmin: RequestHandler): Router {
  const r = Router();

  r.get('/', requireAdmin, (_req: Request, res: Response) => {
    res.json({ invites: userStore.listInvites() });
  });

  r.post('/', requireAdmin, (req: Request, res: Response) => {
    const { role, maxUses, expiresAt } = req.body as {
      role?: Role; maxUses?: number; expiresAt?: number;
    };
    if (!maxUses || !expiresAt) {
      res.status(400).json({ error: 'maxUses and expiresAt required' });
      return;
    }
    const invite = userStore.createInvite(role || 'user', maxUses, expiresAt);
    res.json({ ok: true, invite });
  });

  r.delete('/:code', requireAdmin, (req: Request, res: Response) => {
    userStore.removeInvite(req.params.code!);
    res.json({ ok: true });
  });

  // ── Everybody visibility setting ──

  r.get('/settings/visibility', requireAdmin, (_req: Request, res: Response) => {
    res.json({ everybodyCanRead: userStore.getEverybodyCanRead() });
  });

  r.post('/settings/visibility', requireAdmin, (req: Request, res: Response) => {
    const { everybodyCanRead } = req.body as { everybodyCanRead?: boolean };
    if (typeof everybodyCanRead !== 'boolean') {
      res.status(400).json({ error: 'everybodyCanRead must be a boolean' });
      return;
    }
    userStore.setEverybodyCanRead(everybodyCanRead);
    res.json({ ok: true });
  });

  return r;
}
