/** Shared types used by both the API client and frontend components. */

export type StorageMode = 'persistent' | 'encrypted-persistent' | 'encrypted-portable';
export type NetworkName = 'testnet' | 'mainnet';

export interface SetupState {
  wizardComplete: boolean;
  walletSkipped: boolean;
  walletDontShowAgain: boolean;
  dkgComplete: boolean;
}

export interface WalletPublic {
  p2tr: string;
  tweakedPubKey: string;
  publicKey: string;
  // Note: mnemonic is NEVER sent to frontend
}

export interface PermafrostConfig {
  threshold: number;
  parties: number;
  level: number;
  combinedPubKey: string;
  shareData: string;
}

export interface ContractConfig {
  name: string;
  address: string;
  abi: unknown[];
  methods: string[];
}

export interface HostingConfig {
  domain: string;
  httpsEnabled: boolean;
  httpsStatus?: 'pending' | 'active' | 'error';
  httpsError?: string;
}

export interface VaultConfig {
  version: number;
  network: NetworkName;
  storageMode: StorageMode;
  setupState: SetupState;
  hasAdminPassword?: boolean;
  wallet?: WalletPublic;
  permafrost?: PermafrostConfig;
  contracts: ContractConfig[];
  hosting?: HostingConfig;
}
