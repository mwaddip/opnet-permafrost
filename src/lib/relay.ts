/**
 * RelayClient — E2E encrypted WebSocket relay for multi-party ceremonies.
 *
 * Wraps a WebSocket connection, handles the wire protocol, and provides
 * encrypted messaging via the crypto helpers from relay-crypto.ts.
 * Ceremony components (ThresholdSign, DKGWizard) call send()/broadcast()
 * and listen via on('message', handler) without touching crypto or WS.
 */

import {
  generateECDHKeyPair,
  exportPublicKey,
  importPublicKey,
  deriveAESKey,
  encrypt,
  decrypt,
  toBase64,
  fromBase64,
} from './relay-crypto';

// ---------------------------------------------------------------------------
// Typed event emitter
// ---------------------------------------------------------------------------

type EventMap = {
  joined: [partyId: number, count: number, total: number];
  ready: [pubkeys: Map<number, Uint8Array>];
  message: [from: number, payload: Uint8Array];
  left: [partyId: number];
  reconnected: [partyId: number];
  error: [message: string];
};

// ---------------------------------------------------------------------------
// Wire protocol message types
// ---------------------------------------------------------------------------

interface WireCreated {
  type: 'created';
  session: string;
  partyId: number;
  token: string;
  url: string;
}

interface WireJoined {
  type: 'joined';
  partyId: number;
  count: number;
  total: number;
  /** Present only on the personal joined message sent to the joining party. */
  token?: string;
  session?: string;
}

interface WireReady {
  type: 'ready';
  pubkeys: Record<string, string>; // Go JSON: map[int]string -> {"0":"base64..."}
  threshold: number;
}

interface WireRelay {
  type: 'relay';
  from: number;
  payload: string;
}

interface WireLeft {
  type: 'left';
  partyId: number;
}

interface WireReconnected {
  type: 'reconnected';
  partyId: number;
}

interface WireError {
  type: 'error';
  message: string;
}

type WireMessage =
  | WireCreated
  | WireJoined
  | WireReady
  | WireRelay
  | WireLeft
  | WireReconnected
  | WireError;

// ---------------------------------------------------------------------------
// Session storage key
// ---------------------------------------------------------------------------

const STORAGE_KEY = 'permafrost-relay-token';

function storeToken(session: string, token: string): void {
  try {
    sessionStorage.setItem(`${STORAGE_KEY}:${session}`, token);
  } catch {
    // sessionStorage may be unavailable (e.g. in tests)
  }
}

function loadToken(session: string): string | null {
  try {
    return sessionStorage.getItem(`${STORAGE_KEY}:${session}`);
  } catch {
    return null;
  }
}

function clearToken(session: string): void {
  try {
    sessionStorage.removeItem(`${STORAGE_KEY}:${session}`);
  } catch {
    // ignore
  }
}

// ---------------------------------------------------------------------------
// RelayClient
// ---------------------------------------------------------------------------

export class RelayClient {
  /** Party index assigned by the server. */
  partyId = -1;

  /** All parties and their connection status. */
  parties = new Map<number, { connected: boolean }>();

  /** True after the `ready` message has been processed and AES keys derived. */
  isReady = false;

  /** The session code (e.g. "X7K2M9"). */
  sessionCode = '';

  // -- Private state --------------------------------------------------------

  private readonly relayUrl: string;
  private ws: WebSocket | null = null;
  private keypair: CryptoKeyPair | null = null;
  private peerKeys = new Map<number, CryptoKey>(); // AES keys per peer
  private token: string | null = null;
  private reconnecting = false;
  private reconnectAttempts = 0;
  private readonly maxReconnectAttempts = 10;
  private closed = false;

  private listeners = new Map<string, Set<(...args: unknown[]) => void>>();
  /** Resolves when handleReady finishes; relay messages wait on this. */
  private readyGate: Promise<void> | null = null;

  constructor(relayUrl: string) {
    this.relayUrl = relayUrl;
  }

  // -- Events ---------------------------------------------------------------

  on<K extends keyof EventMap>(
    event: K,
    fn: (...args: EventMap[K]) => void,
  ): void {
    if (!this.listeners.has(event)) this.listeners.set(event, new Set());
    this.listeners.get(event)!.add(fn as (...args: unknown[]) => void);
  }

  off<K extends keyof EventMap>(
    event: K,
    fn: (...args: EventMap[K]) => void,
  ): void {
    this.listeners.get(event)?.delete(fn as (...args: unknown[]) => void);
  }

  private emit<K extends keyof EventMap>(event: K, ...args: EventMap[K]): void {
    this.listeners.get(event)?.forEach((fn) => fn(...args));
  }

  // -- Lifecycle ------------------------------------------------------------

  /**
   * Create a new relay session. Generates an ECDH keypair, opens a
   * WebSocket, and sends the `create` message.
   * Resolves with the session code and shareable URL.
   */
  async create(
    parties: number,
    threshold: number,
  ): Promise<{ session: string; url: string }> {
    this.keypair = await generateECDHKeyPair();
    const pubBytes = await exportPublicKey(this.keypair.publicKey);

    return new Promise<{ session: string; url: string }>((resolve, reject) => {
      const ws = this.openSocket();

      const onError = (ev: Event) => {
        ws.removeEventListener('error', onError);
        reject(new Error(`WebSocket error during create: ${(ev as ErrorEvent).message ?? 'unknown'}`));
      };
      ws.addEventListener('error', onError);

      const origHandler = this.handleMessage.bind(this);
      this.handleMessage = (msg: WireMessage) => {
        if (msg.type === 'created') {
          ws.removeEventListener('error', onError);
          this.handleMessage = origHandler;

          this.partyId = msg.partyId;
          this.sessionCode = msg.session;
          this.token = msg.token;
          storeToken(msg.session, msg.token);
          this.parties.set(msg.partyId, { connected: true });

          resolve({ session: msg.session, url: msg.url });
          return;
        }
        if (msg.type === 'error') {
          ws.removeEventListener('error', onError);
          this.handleMessage = origHandler;
          reject(new Error(msg.message));
          return;
        }
        // Delegate any other message to the normal handler
        origHandler(msg);
      };

      ws.addEventListener('open', () => {
        this.sendWire({
          type: 'create',
          parties,
          threshold,
          pubkey: toBase64(pubBytes),
        });
      });
    });
  }

  /**
   * Join an existing relay session. Generates an ECDH keypair, opens a
   * WebSocket, and sends the `join` message.
   * Resolves when the server confirms our join (personal `joined` message).
   */
  async join(session: string): Promise<void> {
    this.sessionCode = session;
    this.keypair = await generateECDHKeyPair();
    const pubBytes = await exportPublicKey(this.keypair.publicKey);

    return new Promise<void>((resolve, reject) => {
      const ws = this.openSocket();

      const onError = (ev: Event) => {
        ws.removeEventListener('error', onError);
        reject(new Error(`WebSocket error during join: ${(ev as ErrorEvent).message ?? 'unknown'}`));
      };
      ws.addEventListener('error', onError);

      const origHandler = this.handleMessage.bind(this);
      this.handleMessage = (msg: WireMessage) => {
        if (msg.type === 'joined') {
          // The server sends a personal `joined` for us; detect it
          // by checking if we haven't been assigned an ID yet.
          if (this.partyId === -1) {
            ws.removeEventListener('error', onError);
            this.handleMessage = origHandler;

            this.partyId = msg.partyId;
            // The personal joined message includes the reconnection token
            if (msg.token) {
              this.token = msg.token;
              storeToken(session, msg.token);
            }
            this.parties.set(msg.partyId, { connected: true });
            resolve();
            // Re-dispatch this message so normal handler tracks count
            origHandler(msg);
            return;
          }
          origHandler(msg);
          return;
        }
        if (msg.type === 'error') {
          ws.removeEventListener('error', onError);
          this.handleMessage = origHandler;
          reject(new Error(msg.message));
          return;
        }
        origHandler(msg);
      };

      ws.addEventListener('open', () => {
        this.sendWire({
          type: 'join',
          session,
          pubkey: toBase64(pubBytes),
        });
      });
    });
  }

  /** Clean close. */
  close(): void {
    this.closed = true;
    if (this.sessionCode) clearToken(this.sessionCode);
    if (this.ws) {
      this.ws.close(1000, 'client close');
      this.ws = null;
    }
    this.keypair = null;
    this.peerKeys.clear();
  }

  // -- Messaging (E2E encrypted) --------------------------------------------

  /** Send an encrypted payload to a specific peer. */
  async send(to: number, payload: Uint8Array): Promise<void> {
    const aesKey = this.peerKeys.get(to);
    if (!aesKey) throw new Error(`No AES key for party ${to}`);
    const ciphertext = await encrypt(aesKey, payload);
    this.sendWire({
      type: 'relay',
      to,
      payload: toBase64(ciphertext),
    });
  }

  /** Broadcast an encrypted payload to all other parties (N-1 messages). */
  async broadcast(payload: Uint8Array): Promise<void> {
    const promises: Promise<void>[] = [];
    for (const [id] of this.peerKeys) {
      promises.push(this.send(id, payload));
    }
    await Promise.all(promises);
  }

  // -- Private: WebSocket management ----------------------------------------

  private openSocket(): WebSocket {
    const ws = new WebSocket(this.relayUrl);
    this.ws = ws;

    ws.addEventListener('message', (ev: MessageEvent) => {
      try {
        const msg = JSON.parse(String(ev.data)) as WireMessage;
        this.handleMessage(msg);
      } catch {
        this.emit('error', 'Failed to parse relay message');
      }
    });

    ws.addEventListener('close', () => {
      if (!this.closed) {
        this.attemptReconnect();
      }
    });

    return ws;
  }

  /** Normal message dispatcher (may be temporarily overridden during create/join). */
  private handleMessage = (msg: WireMessage): void => {
    switch (msg.type) {
      case 'created':
        // Should not arrive here after initial setup
        break;

      case 'joined':
        this.parties.set(msg.partyId, { connected: true });
        this.emit('joined', msg.partyId, msg.count, msg.total);
        break;

      case 'ready':
        // Store the promise so relay messages can wait for AES keys
        this.readyGate = this.handleReady(msg);
        break;

      case 'relay':
        // If handleReady is still deriving AES keys, wait for it before
        // attempting decryption. Without this gate, relay messages that
        // arrive during key derivation would be silently dropped.
        if (this.readyGate) {
          void this.readyGate.then(() => this.handleRelay(msg));
        } else {
          void this.handleRelay(msg);
        }
        break;

      case 'left':
        this.parties.set(msg.partyId, { connected: false });
        this.emit('left', msg.partyId);
        break;

      case 'reconnected':
        this.parties.set(msg.partyId, { connected: true });
        this.emit('reconnected', msg.partyId);
        break;

      case 'error':
        this.emit('error', msg.message);
        break;
    }
  };

  /** Process `ready` message: import peer pubkeys and derive AES keys. */
  private async handleReady(msg: WireReady): Promise<void> {
    if (!this.keypair) {
      this.emit('error', 'Encryption keys lost — ceremony must restart');
      return;
    }

    const pubkeyMap = new Map<number, Uint8Array>();

    for (const [idStr, b64] of Object.entries(msg.pubkeys)) {
      const peerId = parseInt(idStr, 10);
      const rawPub = fromBase64(b64);
      pubkeyMap.set(peerId, rawPub);

      // Ensure parties map is complete (joiners miss earlier joined events)
      if (!this.parties.has(peerId)) {
        this.parties.set(peerId, { connected: true });
      }

      // Derive AES key for each peer (skip ourselves)
      if (peerId !== this.partyId) {
        const importedPub = await importPublicKey(rawPub);
        const aesKey = await deriveAESKey(
          this.keypair.privateKey,
          importedPub,
          this.sessionCode,
        );
        this.peerKeys.set(peerId, aesKey);
      }
    }

    this.isReady = true;
    this.emit('ready', pubkeyMap);
  }

  /** Process incoming `relay` message: decrypt and emit. */
  private async handleRelay(msg: WireRelay): Promise<void> {
    const aesKey = this.peerKeys.get(msg.from);
    if (!aesKey) {
      this.emit('error', `Received relay from unknown party ${msg.from}`);
      return;
    }
    try {
      const ciphertext = fromBase64(msg.payload);
      const plaintext = await decrypt(aesKey, ciphertext);
      this.emit('message', msg.from, plaintext);
    } catch {
      this.emit('error', `Decryption failed for message from party ${msg.from}`);
    }
  }

  /** Send a raw wire-protocol JSON message over the WebSocket. */
  private sendWire(msg: Record<string, unknown>): void {
    if (!this.ws || this.ws.readyState !== WebSocket.OPEN) {
      this.emit('error', 'WebSocket is not open');
      return;
    }
    this.ws.send(JSON.stringify(msg));
  }

  // -- Private: Reconnection ------------------------------------------------

  private attemptReconnect(): void {
    if (this.reconnecting || this.closed) return;
    this.reconnecting = true;

    // Key-loss detection: if ECDH keypair is gone (page reload), cannot recover
    if (!this.keypair) {
      this.emit('error', 'Encryption keys lost — ceremony must restart');
      this.reconnecting = false;
      return;
    }

    const token = this.token ?? loadToken(this.sessionCode);
    if (!token) {
      this.emit('error', 'No reconnection token — ceremony must restart');
      this.reconnecting = false;
      return;
    }

    if (this.reconnectAttempts >= this.maxReconnectAttempts) {
      this.emit('error', 'Max reconnection attempts reached — ceremony must restart');
      this.reconnecting = false;
      return;
    }

    // Exponential backoff: 1s, 2s, 4s, 8s, ... capped at 30s, plus jitter
    const base = Math.min(1000 * Math.pow(2, this.reconnectAttempts), 30000);
    const delay = base + Math.random() * 1000;
    this.reconnectAttempts++;

    setTimeout(() => {
      if (this.closed) {
        this.reconnecting = false;
        return;
      }

      const ws = new WebSocket(this.relayUrl);
      this.ws = ws;

      ws.addEventListener('open', () => {
        this.sendWire({
          type: 'reconnect',
          session: this.sessionCode,
          token,
        });
        this.reconnecting = false;
        this.reconnectAttempts = 0; // Reset on successful connection
      });

      ws.addEventListener('message', (ev: MessageEvent) => {
        try {
          const msg = JSON.parse(String(ev.data)) as WireMessage;
          this.handleMessage(msg);
        } catch {
          this.emit('error', 'Failed to parse relay message');
        }
      });

      ws.addEventListener('close', () => {
        if (!this.closed) {
          this.reconnecting = false;
          this.attemptReconnect();
        }
      });

      ws.addEventListener('error', () => {
        // The close event will fire next and trigger another reconnect
      });
    }, delay);
  }
}
