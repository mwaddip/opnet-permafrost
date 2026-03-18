import { readFileSync, writeFileSync, existsSync, mkdirSync } from 'node:fs';
import { dirname } from 'node:path';
import { randomBytes } from 'node:crypto';

export type Role = 'admin' | 'user';

export interface User {
  address: string;   // 0x + hex(SHA256(mldsaPubKey)) — NOT p2tr/tweakedPubKey
  role: Role;
  label: string;
}

export interface Invite {
  code: string;
  role: Role;
  usesLeft: number;
  expiresAt: number;  // unix ms
}

interface UserDB {
  users: User[];
  invites: Invite[];
  settings: { everybodyCanRead: boolean };
}

const DATA_DIR = process.env.DATA_DIR || '/data';
const USERS_PATH = `${DATA_DIR}/users.json`;

export class UserStore {
  private db: UserDB = { users: [], invites: [], settings: { everybodyCanRead: true } };

  constructor() {
    this.load();
  }

  private load(): void {
    if (!existsSync(USERS_PATH)) return;
    try {
      this.db = JSON.parse(readFileSync(USERS_PATH, 'utf8'));
    } catch { /* corrupt or missing — start fresh */ }
  }

  private save(): void {
    mkdirSync(dirname(USERS_PATH), { recursive: true });
    writeFileSync(USERS_PATH, JSON.stringify(this.db, null, 2));
  }

  hasUsers(): boolean {
    return this.db.users.length > 0;
  }

  // ── Users ──

  getUser(address: string): User | null {
    return this.db.users.find(u => u.address === address) ?? null;
  }

  addUser(address: string, role: Role, label: string): User {
    if (this.getUser(address)) throw new Error('User already exists');
    const user: User = { address, role, label };
    this.db.users.push(user);
    this.save();
    return user;
  }

  removeUser(address: string): void {
    const before = this.db.users.length;
    this.db.users = this.db.users.filter(u => u.address !== address);
    if (this.db.users.length === before) throw new Error('User not found');
    this.save();
  }

  updateRole(address: string, role: Role): void {
    const user = this.getUser(address);
    if (!user) throw new Error('User not found');
    user.role = role;
    this.save();
  }

  listUsers(): User[] {
    return [...this.db.users];
  }

  // ── Invites ──

  createInvite(role: Role, maxUses: number, expiresAt: number): Invite {
    const code = randomBytes(3).toString('hex').toUpperCase();
    const invite: Invite = { code, role, usesLeft: maxUses, expiresAt };
    this.db.invites.push(invite);
    this.save();
    return invite;
  }

  redeemInvite(code: string, address: string, label: string): User | null {
    const invite = this.db.invites.find(i => i.code === code);
    if (!invite) return null;
    if (Date.now() > invite.expiresAt) return null;
    if (invite.usesLeft <= 0) return null;
    if (this.getUser(address)) return null; // already registered

    invite.usesLeft--;
    if (invite.usesLeft <= 0) {
      this.db.invites = this.db.invites.filter(i => i.code !== code);
    }
    const user = { address, role: invite.role, label };
    this.db.users.push(user);
    this.save();
    return user;
  }

  listInvites(): Invite[] {
    // Clean expired
    const now = Date.now();
    this.db.invites = this.db.invites.filter(i => i.expiresAt > now && i.usesLeft > 0);
    return [...this.db.invites];
  }

  removeInvite(code: string): void {
    this.db.invites = this.db.invites.filter(i => i.code !== code);
    this.save();
  }

  // ── Settings ──

  getEverybodyCanRead(): boolean {
    return this.db.settings.everybodyCanRead;
  }

  setEverybodyCanRead(value: boolean): void {
    this.db.settings.everybodyCanRead = value;
    this.save();
  }
}
