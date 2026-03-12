import { readFileSync, writeFileSync, existsSync, mkdirSync, unlinkSync } from 'node:fs';
import { dirname } from 'node:path';
import { encryptConfig, decryptConfig } from './encryption.js';
import { type VaultConfig, type StorageMode, type NetworkName, defaultConfig } from './types.js';

const DATA_DIR = process.env.DATA_DIR || '/data';
const CONFIG_PATH = `${DATA_DIR}/config.json`;

export class ConfigStore {
  private config: VaultConfig | null = null;
  private storageMode: StorageMode | null = null;

  /** Check if an instance has been initialized */
  isInitialized(): boolean {
    if (this.config) return true;
    return existsSync(CONFIG_PATH);
  }

  /** Initialize a new instance. Called once from the install wizard. */
  init(network: NetworkName, storageMode: StorageMode, password?: string): void {
    if (this.isInitialized()) throw new Error('Already initialized');
    this.config = defaultConfig(network, storageMode);
    this.storageMode = storageMode;
    this.persist(password);
  }

  /** Load config from disk. For encrypted-persistent, requires password. */
  load(password?: string): VaultConfig {
    if (this.config) return this.config;
    if (!existsSync(CONFIG_PATH)) throw new Error('Not initialized');

    const raw = readFileSync(CONFIG_PATH, 'utf8');

    // Try parsing as plaintext JSON first
    try {
      this.config = JSON.parse(raw) as VaultConfig;
      this.storageMode = this.config.storageMode;
      return this.config;
    } catch {
      // Not JSON — must be encrypted
    }

    if (!password) throw new Error('Password required to unlock');
    const decrypted = decryptConfig(raw, password);
    this.config = JSON.parse(decrypted) as VaultConfig;
    this.storageMode = this.config.storageMode;
    return this.config;
  }

  /** Get current config (must be loaded first). */
  get(): VaultConfig {
    if (!this.config) throw new Error('Config not loaded');
    return this.config;
  }

  /** Update config fields and persist. */
  update(patch: Partial<VaultConfig>, password?: string): VaultConfig {
    if (!this.config) throw new Error('Config not loaded');
    this.config = { ...this.config, ...patch };
    if (this.storageMode !== 'encrypted-portable') {
      this.persist(password);
    }
    return this.config;
  }

  /** Import a portable config (decrypted by frontend, sent as JSON). */
  importPortable(config: VaultConfig): void {
    this.config = config;
    this.storageMode = 'encrypted-portable';
    // Do NOT persist to disk — portable mode is memory-only
  }

  /** Export current config as JSON string (frontend will encrypt). */
  exportConfig(): string {
    if (!this.config) throw new Error('Config not loaded');
    return JSON.stringify(this.config);
  }

  /** Wipe all data. */
  reset(): void {
    this.config = null;
    this.storageMode = null;
    if (existsSync(CONFIG_PATH)) unlinkSync(CONFIG_PATH);
  }

  private persist(password?: string): void {
    if (!this.config) return;
    mkdirSync(dirname(CONFIG_PATH), { recursive: true });
    const json = JSON.stringify(this.config, null, 2);

    if (this.config.storageMode === 'encrypted-persistent') {
      if (!password) throw new Error('Password required for encrypted-persistent mode');
      writeFileSync(CONFIG_PATH, encryptConfig(json, password));
    } else if (this.config.storageMode === 'persistent') {
      writeFileSync(CONFIG_PATH, json);
    }
    // encrypted-portable: never write to disk
  }
}
