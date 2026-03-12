export type StorageMode = 'persistent' | 'encrypted-persistent' | 'encrypted-portable';
export type NetworkName = 'testnet' | 'mainnet';

export interface SetupState {
  wizardComplete: boolean;
  walletSkipped: boolean;
  walletDontShowAgain: boolean;
  dkgComplete: boolean;
}

export interface WalletConfig {
  mnemonic: string;
  p2tr: string;
  tweakedPubKey: string;
  publicKey: string;
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

export interface VaultConfig {
  version: number;
  network: NetworkName;
  storageMode: StorageMode;
  setupState: SetupState;
  wallet?: WalletConfig;
  permafrost?: PermafrostConfig;
  contracts: ContractConfig[];
}

export function defaultConfig(network: NetworkName, storageMode: StorageMode): VaultConfig {
  return {
    version: 1,
    network,
    storageMode,
    setupState: {
      wizardComplete: true,
      walletSkipped: false,
      walletDontShowAgain: false,
      dkgComplete: false,
    },
    contracts: [],
  };
}

/** Sanitize config for frontend — strip private keys */
export function sanitizeConfig(config: VaultConfig): Omit<VaultConfig, 'wallet'> & { wallet?: Omit<WalletConfig, 'mnemonic'> } {
  const { wallet, ...rest } = config;
  if (!wallet) return rest;
  const { mnemonic: _, ...safeWallet } = wallet;
  return { ...rest, wallet: safeWallet };
}
