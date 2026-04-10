// sha256("OP_NET") — must match OPNetConsensus.consensus.PROTOCOL_ID
const BITCOIN_PROTOCOL_ID = new Uint8Array([
  0xe7, 0x84, 0x99, 0x5a, 0x41, 0x2d, 0x77, 0x39, 0x88, 0xc4, 0xb8, 0xe3, 0x33, 0xd7, 0xb3, 0x9d,
  0xfb, 0x3c, 0xab, 0xf1, 0x18, 0xd0, 0xd6, 0x45, 0x41, 0x1a, 0x91, 0x6c, 0xa2, 0x40, 0x79, 0x39,
]);

// Chain IDs must match getChainId(getNetwork(name)) from @btc-vision/transaction.
// 'testnet' maps to networks.opnetTestnet (bech32: "opt"), NOT networks.testnet (bech32: "tb").
const CHAIN_IDS: Record<string, Uint8Array> = {
  mainnet: new Uint8Array([
    0x00, 0x00, 0x00, 0x00, 0x00, 0x19, 0xd6, 0x68, 0x9c, 0x08, 0x5a, 0xe1, 0x65, 0x83,
    0x1e, 0x93, 0x4f, 0xf7, 0x63, 0xae, 0x46, 0xa2, 0xa6, 0xc1, 0x72, 0xb3, 0xf1, 0xb6,
    0x0a, 0x8c, 0xe2, 0x6f,
  ]),
  testnet: new Uint8Array([
    0x00, 0x00, 0x01, 0x7f, 0x85, 0x10, 0x6b, 0x1f, 0xee, 0xaf, 0x2f, 0x70, 0xf1, 0xe2,
    0xb8, 0x05, 0x98, 0x5b, 0xb5, 0x75, 0xf8, 0x8f, 0x9b, 0x0b, 0xa5, 0x75, 0x3d, 0x2f,
    0x3c, 0xf1, 0x32, 0x73,
  ]),
};

async function sha256(data: Uint8Array): Promise<Uint8Array> {
  const hash = await crypto.subtle.digest('SHA-256', data as unknown as ArrayBuffer);
  return new Uint8Array(hash);
}

/** Drop the prefix byte from a 33-byte SEC1 compressed key to 32-byte x-only */
function toXOnly(pubkey: Uint8Array): Uint8Array {
  return pubkey.length === 33 ? pubkey.slice(1) : pubkey;
}

/**
 * Compute the SHA-256 hash of the OPNet key-link message.
 * This hash is what the FROST ceremony must sign (with tweaked key).
 *
 * Layout matches TransactionBuilder.generateLegacySignature() exactly:
 *   [LEVEL2=0x2C][SHA256(mldsaPubKey)][tweakedXOnly][untweakedCompressed][PROTOCOL_ID][chainId]
 */
export async function computeKeyLinkHash(
  mldsaPubKey: Uint8Array,
  frostAggregateKey: Uint8Array,   // 33 bytes SEC1 compressed (tweaked)
  frostUntweakedKey: Uint8Array,   // 33 bytes SEC1 compressed
  network: string,
): Promise<Uint8Array> {
  const chainId = CHAIN_IDS[network];
  if (!chainId) throw new Error(`No chain ID for network: ${network}`);

  const hashedPubKey = await sha256(mldsaPubKey);
  const tweakedXOnly = toXOnly(frostAggregateKey);

  const parts = [
    new Uint8Array([0x2C]), // MLDSASecurityLevel.LEVEL2 = 44
    hashedPubKey,           // 32 bytes
    tweakedXOnly,           // 32 bytes
    frostUntweakedKey,      // 33 bytes
    BITCOIN_PROTOCOL_ID,    // 32 bytes
    chainId,                // 32 bytes
  ];

  const totalLen = parts.reduce((sum, p) => sum + p.length, 0);
  const message = new Uint8Array(totalLen);
  let offset = 0;
  for (const part of parts) {
    message.set(part, offset);
    offset += part.length;
  }

  return sha256(message);
}
