import { useState, useEffect, useCallback, useRef } from 'react';
import { MessageBuilder, type MessageMeta } from './MessageBuilder';
import { ShareImport, ThresholdSign } from './ThresholdSign';
import { RelayClient } from '../lib/relay';
import { getConfig, getWalletBalance, broadcastTx, getBroadcastStatus } from '../lib/api';
import { toHex } from '../lib/threshold';
import type { VaultConfig } from '../lib/vault-types';
import type { DecryptedShare } from '../lib/share-crypto';
import type { SendPrefill } from '../App';
import { OtziWordmark, ThemeToggle } from '../App';

const RELAY_URL = import.meta.env.VITE_RELAY_URL as string || 'ws://localhost:8080/ws';
const TXMSG_PREFIX = 'TXMSG:';

interface Props {
  onSettings: () => void;
  prefill?: SendPrefill | null;
  onPrefillConsumed?: () => void;
}

type Phase = 'build' | 'sign' | 'result';
type RelayState = 'none' | 'creating' | 'joining' | 'waiting' | 'ready';

export function SigningPage({ onSettings, prefill, onPrefillConsumed }: Props) {
  const [config, setConfig] = useState<VaultConfig | null>(null);
  const [balance, setBalance] = useState<string | null>(null);
  const [phase, setPhase] = useState<Phase>('build');
  const [message, setMessage] = useState<Uint8Array | null>(null);
  const [messageMeta, setMessageMeta] = useState<MessageMeta | null>(null);
  const [signature, setSignature] = useState<string | null>(null);
  const [txResult, setTxResult] = useState<{ transactionId?: string; error?: string; alreadyBroadcast?: boolean } | null>(null);
  const [broadcasting, setBroadcasting] = useState(false);

  // Role: did this party build the message (initiator) or join with a code (joiner)?
  const [isInitiator, setIsInitiator] = useState(false);

  // Relay state
  const [relayState, setRelayState] = useState<RelayState>('none');
  const [relayClient, setRelayClient] = useState<RelayClient | null>(null);
  const [relaySessionCode, setRelaySessionCode] = useState('');
  const [relayJoinCode, setRelayJoinCode] = useState('');
  const [relayError, setRelayError] = useState('');
  const [pendingJoinCode, setPendingJoinCode] = useState('');
  const [relayPartyCount, setRelayPartyCount] = useState(0);
  const [relayPartyTotal, setRelayPartyTotal] = useState(0);
  const [relayReady, setRelayReady] = useState(false);
  const [share, setShare] = useState<DecryptedShare | null>(null);
  const relayClientRef = useRef<RelayClient | null>(null);
  const autoJoinRef = useRef(false);
  const messageBroadcastRef = useRef(false);

  useEffect(() => {
    getConfig().then(setConfig).catch(console.error);
  }, []);

  // Poll balance every 30s if wallet is configured
  useEffect(() => {
    if (!config?.wallet) return;
    const fetch = () => getWalletBalance().then(r => setBalance(r.balance)).catch(() => {});
    fetch();
    const interval = setInterval(fetch, 30_000);
    return () => clearInterval(interval);
  }, [config?.wallet]);

  // Cleanup relay on unmount
  useEffect(() => {
    return () => {
      relayClientRef.current?.close();
    };
  }, []);

  // ── Initiator: broadcast message to all parties once relay is ready ──
  useEffect(() => {
    if (!isInitiator || !relayReady || !relayClient || !message || !messageMeta) return;
    if (messageBroadcastRef.current) return;
    messageBroadcastRef.current = true;

    const msgHex = toHex(message);
    const payload = TXMSG_PREFIX + btoa(JSON.stringify({ message: msgHex, meta: messageMeta }));
    const payloadBytes = new TextEncoder().encode(payload);
    relayClient.broadcast(payloadBytes).catch(err => {
      console.error('Failed to broadcast message:', err);
    });
  }, [isInitiator, relayReady, relayClient, message, messageMeta]);

  // ── Joiner: listen for message from initiator via relay ──
  useEffect(() => {
    if (isInitiator || !relayClient) return;

    const handler = (_from: number, payload: Uint8Array) => {
      const text = new TextDecoder().decode(payload);
      if (!text.startsWith(TXMSG_PREFIX)) return;

      try {
        const json = JSON.parse(atob(text.slice(TXMSG_PREFIX.length)));
        const msgHex: string = json.message;
        const meta: MessageMeta = json.meta;
        const msgBytes = new Uint8Array(msgHex.match(/.{2}/g)!.map(b => parseInt(b, 16)));
        setMessage(msgBytes);
        setMessageMeta(meta);
      } catch (err) {
        console.error('Failed to parse message from initiator:', err);
      }
    };

    relayClient.on('message', handler);
    return () => { relayClient.off('message', handler); };
  }, [isInitiator, relayClient]);

  const handleMessageBuilt = useCallback((msg: Uint8Array, meta: MessageMeta) => {
    setMessage(msg);
    setMessageMeta(meta);
    setIsInitiator(true);
    setPhase('sign');
  }, []);

  // Joiner: enter session code → skip build, go straight to sign phase
  const handleJoinSession = useCallback(() => {
    if (pendingJoinCode.length < 6) return;
    setIsInitiator(false);
    setPhase('sign');
  }, [pendingJoinCode]);

  const handleSignatureReady = useCallback((sig: Uint8Array) => {
    setSignature(toHex(sig));
    setRelayClient(null);
    relayClientRef.current?.close();
    relayClientRef.current = null;
    setPhase('result');
  }, []);

  // Check if another party already broadcast this tx
  useEffect(() => {
    if (phase !== 'result' || !messageMeta?.messageHash || txResult) return;
    getBroadcastStatus(messageMeta.messageHash).then(status => {
      if (status.broadcast && status.transactionId) {
        setTxResult({ transactionId: status.transactionId, alreadyBroadcast: true });
      }
    }).catch(() => {});
  }, [phase, messageMeta, txResult]);

  const handleBroadcast = async () => {
    if (!messageMeta || !signature) return;
    setBroadcasting(true);
    try {
      const result = await broadcastTx({
        contract: messageMeta.contractAddress,
        method: messageMeta.method,
        params: Object.values(messageMeta.params),
        paramTypes: messageMeta.paramTypes,
        signature,
        messageHash: messageMeta.messageHash,
      }) as { transactionId?: string; error?: string; alreadyBroadcast?: boolean };
      setTxResult(result);
    } catch (e) {
      setTxResult({ error: (e as Error).message });
    } finally {
      setBroadcasting(false);
    }
  };

  const handleReset = () => {
    relayClientRef.current?.close();
    relayClientRef.current = null;
    setRelayClient(null);
    setRelayState('none');
    setRelaySessionCode('');
    setRelayJoinCode('');
    setRelayError('');
    setRelayPartyCount(0);
    setRelayPartyTotal(0);
    setRelayReady(false);
    setShare(null);
    setPhase('build');
    setMessage(null);
    setMessageMeta(null);
    setSignature(null);
    setTxResult(null);
    setPendingJoinCode('');
    setIsInitiator(false);
    autoJoinRef.current = false;
    messageBroadcastRef.current = false;
  };

  // ── Relay: Create Session ──
  const handleRelayCreate = useCallback(async () => {
    if (!share) return;
    setRelayError('');
    setRelayState('creating');

    const client = new RelayClient(RELAY_URL);
    relayClientRef.current = client;

    client.on('joined', (_partyId, count, total) => {
      setRelayPartyCount(count);
      setRelayPartyTotal(total);
    });

    client.on('ready', () => {
      setRelayReady(true);
      setRelayState('ready');
    });

    client.on('error', (errMsg) => {
      setRelayError(errMsg);
    });

    try {
      const result = await client.create(share.threshold, share.threshold);
      setRelaySessionCode(result.session);
      setRelayClient(client);
      setRelayState('waiting');
      setRelayPartyCount(1);
      setRelayPartyTotal(share.threshold);
    } catch (err) {
      setRelayError(err instanceof Error ? err.message : 'Failed to create relay session');
      setRelayState('none');
      client.close();
      relayClientRef.current = null;
    }
  }, [share]);

  // ── Relay: Join Session ──
  const handleRelayJoin = useCallback(async (code?: string) => {
    const joinCode = (code || relayJoinCode).trim();
    if (!joinCode) return;
    setRelayError('');
    setRelayState('joining');

    const client = new RelayClient(RELAY_URL);
    relayClientRef.current = client;

    client.on('joined', (_partyId, count, total) => {
      setRelayPartyCount(count);
      setRelayPartyTotal(total);
    });

    client.on('ready', () => {
      setRelayReady(true);
      setRelayState('ready');
    });

    client.on('error', (errMsg) => {
      setRelayError(errMsg);
    });

    try {
      await client.join(joinCode);
      setRelayClient(client);
      setRelayState('waiting');
    } catch (err) {
      setRelayError(err instanceof Error ? err.message : 'Failed to join relay session');
      setRelayState('none');
      client.close();
      relayClientRef.current = null;
    }
  }, [relayJoinCode]);

  // ── Auto-join relay when share is loaded with a pending join code ──
  useEffect(() => {
    if (autoJoinRef.current) return;
    if (!share || !pendingJoinCode || pendingJoinCode.length < 6) return;
    if (relayState !== 'none') return;
    autoJoinRef.current = true;
    handleRelayJoin(pendingJoinCode);
  }, [share, pendingJoinCode, relayState, handleRelayJoin]);

  if (!config) return <div className="ceremony"><div className="spinner" /></div>;

  return (
    <div className="ceremony" style={{ maxWidth: 720 }}>
      {/* Header */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 24 }}>
        <div>
          <OtziWordmark height={32} />
          <p className="subtitle" style={{ marginBottom: 0, marginTop: 2 }}>
            {config.network === 'testnet' ? 'Testnet' : 'Mainnet'}
            {config.permafrost ? ` · ${config.permafrost.threshold}-of-${config.permafrost.parties}` : ''}
          </p>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
          {balance !== null && (
            <div style={{ fontSize: 13, color: 'var(--white-dim)' }}>
              {(parseInt(balance) / 1e8).toFixed(8)} BTC
            </div>
          )}
          <ThemeToggle />
          <button
            onClick={onSettings}
            style={{ background: 'none', color: 'var(--gray-light)', fontSize: 20, padding: 4 }}
            title="Settings"
          >
            ⚙
          </button>
        </div>
      </div>

      {/* Build phase */}
      {phase === 'build' && (
        <>
          <MessageBuilder
            contracts={config.contracts}
            onMessageBuilt={handleMessageBuilt}
            prefill={prefill}
            onPrefillConsumed={onPrefillConsumed}
          />

          {/* Divider */}
          <div style={{ textAlign: 'center', fontSize: 13, color: 'var(--gray-light)', margin: '16px 0' }}>
            or join an existing signing session
          </div>

          {/* Session code join — other parties paste the code here */}
          <div className="card">
            <h2>Join Signing Session</h2>
            <p style={{ fontSize: 13, color: 'var(--white-dim)', marginBottom: 12 }}>
              Paste the session code shared by the initiating party.
            </p>
            <div style={{ display: 'flex', gap: 8 }}>
              <input
                autoFocus
                value={pendingJoinCode}
                onChange={e => {
                  const val = e.target.value.toUpperCase().replace(/[^A-Z0-9]/g, '');
                  setPendingJoinCode(val);
                  if (val.length >= 6) {
                    setIsInitiator(false);
                    setPhase('sign');
                  }
                }}
                placeholder="Session code"
                style={{ flex: 1, letterSpacing: 2, fontSize: 16, textAlign: 'center' }}
                onKeyDown={e => e.key === 'Enter' && handleJoinSession()}
              />
              <button
                className="btn btn-primary"
                onClick={handleJoinSession}
                disabled={pendingJoinCode.length < 6}
              >
                Join
              </button>
            </div>
          </div>
        </>
      )}

      {/* Sign phase */}
      {phase === 'sign' && (
        <>
          {/* Signing info header (initiator has message, joiner waits for it) */}
          <div className="card" style={{ marginBottom: 16 }}>
            {messageMeta ? (
              <>
                <h2>Signing: {messageMeta.method}</h2>
                <div style={{ fontSize: 13, color: 'var(--white-dim)' }}>
                  Contract: <span style={{ fontFamily: 'monospace' }}>{messageMeta.contractAddress}</span>
                </div>
                <div style={{ fontSize: 13, color: 'var(--white-dim)', marginTop: 4 }}>
                  Message hash: <span style={{ fontFamily: 'monospace', color: 'var(--accent)' }}>{messageMeta.messageHash.slice(0, 16)}...</span>
                </div>
              </>
            ) : (
              <>
                <h2>Joining Session</h2>
                <div style={{ fontSize: 13, color: 'var(--white-dim)' }}>
                  Session: <span style={{ fontFamily: 'monospace', letterSpacing: 2 }}>{pendingJoinCode}</span>
                </div>
              </>
            )}
            <button className="btn btn-secondary" style={{ marginTop: 12, fontSize: 13 }} onClick={handleReset}>
              Cancel
            </button>
          </div>

          {/* Step 1: Upload share */}
          {!share && (
            <ShareImport onShareLoaded={setShare} />
          )}

          {/* Share info badge */}
          {share && (
            <div className="threshold-share-info" style={{ marginBottom: 16 }}>
              <span className="threshold-share-badge">
                Party {share.partyId} | {share.threshold}-of-{share.parties}
              </span>
              <button
                className="threshold-clear-btn"
                onClick={() => { setShare(null); setRelayState('none'); setRelayClient(null); relayClientRef.current?.close(); relayClientRef.current = null; setRelayReady(false); setRelayError(''); autoJoinRef.current = false; }}
                title="Clear share and re-import"
              >
                Clear
              </button>
            </div>
          )}

          {/* Step 2: Relay session (after share loaded, before signing starts) */}
          {share && !relayReady && (
            <div className="card">
              <h2>Signing Session</h2>
              <p style={{ fontSize: 13, color: 'var(--white-dim)', marginBottom: 16 }}>
                {share.threshold}-of-{share.parties} threshold signing requires {share.threshold} parties to connect via relay.
              </p>

              {relayState === 'none' && isInitiator && (
                <button
                  className="btn btn-primary btn-full"
                  onClick={handleRelayCreate}
                >
                  Create Signing Session
                </button>
              )}

              {(relayState === 'creating' || relayState === 'joining') && (
                <div style={{ textAlign: 'center', padding: 16 }}>
                  <span className="spinner" />
                  <div style={{ marginTop: 8, fontSize: 13, color: 'var(--white-dim)' }}>Connecting...</div>
                </div>
              )}

              {relayState === 'waiting' && (
                <div style={{ textAlign: 'center' }}>
                  {relaySessionCode && (
                    <div style={{ marginBottom: 16 }}>
                      <div style={{ fontSize: 13, color: 'var(--gray-light)', marginBottom: 4 }}>Session Code</div>
                      <div
                        className="pubkey-display"
                        style={{ fontSize: 24, letterSpacing: 4, cursor: 'pointer' }}
                        onClick={() => navigator.clipboard.writeText(relaySessionCode)}
                        title="Click to copy"
                      >
                        {relaySessionCode}
                      </div>
                      <div style={{ fontSize: 12, color: 'var(--gray-light)', marginTop: 4 }}>
                        Share this code with other signers
                      </div>
                    </div>
                  )}
                  <div style={{ fontSize: 14, fontWeight: 600 }}>
                    Waiting for parties... ({relayPartyCount}/{relayPartyTotal})
                  </div>
                  <div style={{ display: 'flex', justifyContent: 'center', gap: 6, marginTop: 12 }}>
                    {Array.from({ length: relayPartyTotal }, (_, i) => (
                      <div
                        key={i}
                        style={{
                          width: 10, height: 10, borderRadius: '50%',
                          background: i < relayPartyCount ? 'var(--accent)' : 'var(--gray-dark)',
                        }}
                      />
                    ))}
                  </div>
                </div>
              )}

              {relayError && <div className="warning" style={{ marginTop: 12 }}>{relayError}</div>}
            </div>
          )}

          {/* Waiting for message from initiator (joiner only, relay ready but no message yet) */}
          {share && relayReady && !message && !isInitiator && (
            <div className="card" style={{ textAlign: 'center', padding: 24 }}>
              <span className="spinner" />
              <div style={{ marginTop: 12, fontSize: 14, fontWeight: 600 }}>
                Waiting for transaction details from initiator...
              </div>
              <div style={{ marginTop: 4, fontSize: 13, color: 'var(--white-dim)' }}>
                The initiating party will broadcast the message to sign.
              </div>
            </div>
          )}

          {/* Step 3: Threshold signing (after relay is ready AND message is available) */}
          {share && relayReady && relayClient && message && messageMeta && (
            <ThresholdSign
              stepTitle={`Sign: ${messageMeta.method}`}
              targetContract={messageMeta.contractAddress}
              txParams={messageMeta.params}
              message={message}
              share={share}
              onSignatureReady={handleSignatureReady}
              onCancel={handleReset}
              relayClient={relayClient}
              relayReady={relayReady}
              relayPartyId={relayClient.partyId}
            />
          )}
        </>
      )}

      {/* Result phase */}
      {phase === 'result' && signature && messageMeta && (
        <div className="card">
          <h2>Signature Ready</h2>
          <div className="success-box">Threshold signing complete</div>

          <h3 style={{ fontSize: 14, fontWeight: 600, marginBottom: 8 }}>Message Hash</h3>
          <div className="pubkey-display" style={{ fontSize: 12 }}>{messageMeta.messageHash}</div>

          <h3 style={{ fontSize: 14, fontWeight: 600, marginBottom: 8 }}>ML-DSA Signature</h3>
          <div className="pubkey-display" style={{ fontSize: 11, maxHeight: 120, overflowY: 'auto' }}>{signature}</div>

          <button
            className="btn btn-secondary btn-full"
            style={{ marginBottom: 12 }}
            onClick={() => navigator.clipboard.writeText(signature)}
          >
            Copy Signature
          </button>

          {/* Broadcast button — only if wallet is configured */}
          {config.wallet && !txResult && (
            <button className="btn btn-primary btn-full" onClick={handleBroadcast} disabled={broadcasting}>
              {broadcasting ? <span className="spinner" /> : 'Broadcast Transaction'}
            </button>
          )}

          {txResult && (
            <div className={txResult.transactionId ? 'success-box' : 'warning'}>
              {txResult.transactionId
                ? `${txResult.alreadyBroadcast ? 'Already broadcast by another party' : 'Transaction broadcast'}: ${txResult.transactionId}`
                : `Broadcast failed: ${txResult.error}`}
            </div>
          )}

          <button className="btn btn-secondary btn-full" style={{ marginTop: 12 }} onClick={handleReset}>
            New Transaction
          </button>
        </div>
      )}
    </div>
  );
}
