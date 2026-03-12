import { useState, useCallback, useRef, useEffect } from 'react';
import type { ShareFile, DecryptedShare } from '../lib/share-crypto';
import { decryptShareFile } from '../lib/share-crypto';
import {
  createSession,
  round1,
  round2,
  round3,
  combine,
  addBlob,
  destroySession,
} from '../lib/threshold';
import type { SigningSession } from '../lib/threshold';
import type { RelayClient } from '../lib/relay';

// ---------------------------------------------------------------------------
// Share import
// ---------------------------------------------------------------------------

interface ShareImportProps {
  onShareLoaded: (share: DecryptedShare) => void;
}

function ShareImport({ onShareLoaded }: ShareImportProps) {
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  const [fileName, setFileName] = useState('');
  const fileRef = useRef<ShareFile | null>(null);

  const handleFile = useCallback((e: React.ChangeEvent<HTMLInputElement>) => {
    setError('');
    const file = e.target.files?.[0];
    if (!file) return;
    setFileName(file.name);

    const reader = new FileReader();
    reader.onload = () => {
      try {
        fileRef.current = JSON.parse(reader.result as string) as ShareFile;
      } catch {
        setError('Invalid share file (not valid JSON)');
        fileRef.current = null;
      }
    };
    reader.readAsText(file);
  }, []);

  const handleDecrypt = useCallback(async () => {
    if (!fileRef.current) {
      setError('Load a share file first');
      return;
    }
    if (!password) {
      setError('Enter your password');
      return;
    }

    setLoading(true);
    setError('');
    try {
      const share = await decryptShareFile(fileRef.current, password);
      onShareLoaded(share);
    } catch {
      setError('Decryption failed — wrong password or corrupted file');
    } finally {
      setLoading(false);
    }
  }, [password, onShareLoaded]);

  return (
    <div className="threshold-share-import">
      <div className="threshold-section-title">Import Share File</div>
      <p className="threshold-hint">
        Load your encrypted PERMAFROST share file and enter your password to
        unlock it. The share is held in memory only.
      </p>

      <div className="step-field">
        <label>Share File (.json)</label>
        <input type="file" accept=".json" onChange={handleFile} />
        {fileName && <span className="threshold-filename">{fileName}</span>}
      </div>

      <div className="step-field">
        <label>Password</label>
        <input
          type="password"
          placeholder="Share file password"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          onKeyDown={(e) => e.key === 'Enter' && void handleDecrypt()}
        />
      </div>

      {error && <div className="step-status error">{error}</div>}

      <button
        className="step-execute-btn"
        disabled={loading || !fileRef.current}
        onClick={() => void handleDecrypt()}
      >
        {loading ? 'Decrypting...' : 'Unlock Share'}
      </button>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Tx detail display (for co-signers to verify what they're signing)
// ---------------------------------------------------------------------------

interface TxDetailProps {
  stepTitle: string;
  targetContract: string;
  params: Record<string, string>;
}

function TxDetail({ stepTitle, targetContract, params }: TxDetailProps) {
  return (
    <div className="threshold-tx-detail">
      <div className="threshold-section-title">Transaction Details</div>
      <div className="admin-detail-grid" style={{ marginBottom: 0 }}>
        <div className="admin-detail-row">
          <span className="admin-detail-label">Step</span>
          <span className="admin-detail-value">{stepTitle}</span>
        </div>
        <div className="admin-detail-row">
          <span className="admin-detail-label">Contract</span>
          <span className="admin-detail-value truncate">{targetContract}</span>
        </div>
        {Object.entries(params).map(([key, val]) => (
          <div className="admin-detail-row" key={key}>
            <span className="admin-detail-label">{key}</span>
            <span className="admin-detail-value truncate">{val}</span>
          </div>
        ))}
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Party tracker
// ---------------------------------------------------------------------------

interface PartyTrackerProps {
  activePartyIds: number[];
  collected: Map<number, unknown>;
  selfId: number;
}

function PartyTracker({ activePartyIds, collected, selfId }: PartyTrackerProps) {
  return (
    <div className="threshold-collected" style={{ marginBottom: 12 }}>
      {activePartyIds.map((id) => {
        const has = collected.has(id);
        const isSelf = id === selfId;
        return (
          <span
            key={id}
            className={`threshold-collected-chip${has ? '' : ' pending'}`}
            style={!has ? { background: 'rgba(107,107,107,0.15)', color: 'var(--gray-light)' } : undefined}
          >
            Party {id}{isSelf ? ' (you)' : ''}{has ? ' ✓' : ''}
          </span>
        );
      })}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Blob exchange UI
// ---------------------------------------------------------------------------

interface BlobExchangeProps {
  roundNumber: number;
  myBlob: string;
  threshold: number;
  collected: Map<number, unknown>;
  activePartyIds: number[];
  selfId: number;
  onAddBlob: (blob: string) => void;
  onProceed: () => void;
  canProceed: boolean;
  error: string;
}

function BlobExchange({
  roundNumber,
  myBlob,
  threshold,
  collected,
  activePartyIds,
  selfId,
  onAddBlob,
  onProceed,
  canProceed,
  error,
}: BlobExchangeProps) {
  const [importError, setImportError] = useState('');

  const handleDownload = useCallback(() => {
    const blob = new Blob([myBlob], { type: 'application/octet-stream' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `round${roundNumber}-party${selfId}.blob`;
    a.click();
    URL.revokeObjectURL(url);
  }, [myBlob, roundNumber, selfId]);

  const handleFileImport = useCallback((e: React.ChangeEvent<HTMLInputElement>) => {
    setImportError('');
    const file = e.target.files?.[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = () => {
      const text = (reader.result as string).trim();
      if (!text) {
        setImportError('Empty file');
        return;
      }
      onAddBlob(text);
    };
    reader.readAsText(file);
    // Reset input so the same file can be re-selected
    e.target.value = '';
  }, [onAddBlob]);

  const needed = threshold;
  const blobSizeKB = (myBlob.length / 1024).toFixed(0);

  return (
    <div className="threshold-blob-exchange">
      <div className="threshold-section-title">Round {roundNumber}</div>

      <PartyTracker activePartyIds={activePartyIds} collected={collected} selfId={selfId} />

      {/* Download own blob */}
      <div className="step-field">
        <label>Your blob — send this file to co-signers ({blobSizeKB} KB)</label>
        <button className="step-execute-btn" onClick={handleDownload}>
          Download round{roundNumber}-party{selfId}.blob
        </button>
      </div>

      {/* Import co-signer blob */}
      <div className="step-field">
        <label>
          Import co-signer blob file ({collected.size}/{needed} collected)
        </label>
        <input type="file" accept=".blob,.txt" onChange={handleFileImport} />
      </div>

      {(error || importError) && (
        <div className="step-status error">{error || importError}</div>
      )}

      <button
        className="step-execute-btn"
        onClick={onProceed}
        disabled={!canProceed}
        style={{ marginTop: 8 }}
      >
        Proceed to {roundNumber < 3 ? `Round ${roundNumber + 1}` : 'Combine'}
      </button>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Main ThresholdSign component
// ---------------------------------------------------------------------------

type SigningPhase = 'idle' | 'round1' | 'round2' | 'round3' | 'complete' | 'failed';

interface ThresholdSignProps {
  stepTitle: string;
  targetContract: string;
  txParams: Record<string, string>;
  message: Uint8Array;
  share: DecryptedShare;
  onSignatureReady: (signature: Uint8Array) => void;
  onCancel: () => void;
  /** Relay client for WebSocket-based blob exchange (optional — used by relay modes). */
  relayClient?: RelayClient | null;
  /** Party ID assigned by the relay server (optional — used by relay modes). */
  relayPartyId?: number;
}

export function ThresholdSign({
  stepTitle,
  targetContract,
  txParams,
  message,
  share,
  onSignatureReady,
  onCancel,
  relayClient,
  relayPartyId: _relayPartyId,
}: ThresholdSignProps) {
  // relayPartyId is the relay-server-assigned ID (used by the caller for routing);
  // signing logic uses share.partyId (cryptographic identity) and relayClient.parties.
  void _relayPartyId;
  const [phase, setPhase] = useState<SigningPhase>('idle');
  const [session, setSession] = useState<SigningSession | null>(null);
  const [blobError, setBlobError] = useState('');
  const [activePartyIds, setActivePartyIds] = useState<number[]>([]);
  const [partyInput, setPartyInput] = useState('');

  // Cleanup on unmount
  const sessionRef = useRef<SigningSession | null>(null);
  useEffect(() => {
    return () => {
      if (sessionRef.current) {
        destroySession(sessionRef.current);
      }
    };
  }, []);

  // Ref to track whether relay auto-init has fired (prevent double-start)
  const relayInitRef = useRef(false);

  // Parse active party IDs from comma-separated input.
  // The threshold library requires EXACTLY T active parties (not more).
  const parsePartyIds = useCallback((): number[] | null => {
    const parts = partyInput.split(',').map(s => parseInt(s.trim(), 10)).filter(n => !isNaN(n));
    // Ensure our own ID is included
    if (!parts.includes(share.partyId)) {
      parts.push(share.partyId);
    }
    const unique = [...new Set(parts)].sort((a, b) => a - b);
    if (unique.length !== share.threshold) return null;
    return unique;
  }, [partyInput, share.partyId, share.threshold]);

  // Helper: broadcast a blob string via relay (returns promise)
  const broadcastBlob = useCallback(async (blob: string): Promise<void> => {
    if (!relayClient) return;
    const blobBytes = new TextEncoder().encode(blob);
    await relayClient.broadcast(blobBytes);
  }, [relayClient]);

  // Track whether our current round's blob has been sent
  const [roundBlobSent, setRoundBlobSent] = useState(false);

  // Barrier synchronization: each party broadcasts BARRIER:<round>:<partyId>
  // after sending its blob AND collecting all expected blobs. No party advances
  // until all T barriers for the current round are received.
  const [barriers, setBarriers] = useState<Record<string, Set<number>>>({});
  const barrierSentRef = useRef<Record<string, boolean>>({});

  // Start signing (shared between manual and relay modes)
  const startSigningWithIds = useCallback((ids: number[]) => {
    setActivePartyIds(ids);
    const sess = createSession(message, share, ids);
    const blob = round1(sess);
    sessionRef.current = sess;
    setSession({ ...sess });
    setPhase('round1');
    setRoundBlobSent(false);

    // In relay mode, auto-broadcast round 1 blob (await before marking sent)
    if (relayClient && blob) {
      void (async () => {
        const blobBytes = new TextEncoder().encode(blob);
        await relayClient.broadcast(blobBytes);
        setRoundBlobSent(true);
      })();
    }
  }, [message, share, relayClient]);

  // Start signing (manual mode — parses party IDs from input)
  const startSigning = useCallback(() => {
    const ids = parsePartyIds();
    if (!ids || ids.length < share.threshold) return;
    startSigningWithIds(ids);
  }, [share.threshold, parsePartyIds, startSigningWithIds]);

  // Current round number for validation
  const currentRound = phase === 'round1' ? 1 : phase === 'round2' ? 2 : phase === 'round3' ? 3 : undefined;

  // Add blob from co-signer
  const handleAddBlob = useCallback((blob: string) => {
    if (!sessionRef.current) return;
    setBlobError('');
    const result = addBlob(sessionRef.current, blob, currentRound);
    if (!result.ok) {
      setBlobError(result.error ?? 'Invalid blob');
      return;
    }
    setSession({ ...sessionRef.current });
  }, [currentRound]);

  // Advance to round 2
  const advanceToRound2 = useCallback(() => {
    if (!sessionRef.current) return;
    try {
      round2(sessionRef.current);
      setSession({ ...sessionRef.current });
      setPhase('round2');
      setBlobError('');
      setRoundBlobSent(false);

      // Auto-broadcast round 2 blob in relay mode (await before marking sent)
      if (relayClient && sessionRef.current.myRound2Blob) {
        void (async () => {
          await broadcastBlob(sessionRef.current!.myRound2Blob!);
          setRoundBlobSent(true);
        })();
      }
    } catch (err) {
      setBlobError(err instanceof Error ? err.message : 'Round 2 failed');
    }
  }, [relayClient, broadcastBlob]);

  // Advance to round 3
  const advanceToRound3 = useCallback(() => {
    if (!sessionRef.current) return;
    try {
      round3(sessionRef.current);
      setSession({ ...sessionRef.current });
      setPhase('round3');
      setBlobError('');
      setRoundBlobSent(false);

      // Auto-broadcast round 3 blob in relay mode (await before marking sent)
      if (relayClient && sessionRef.current.myRound3Blob) {
        void (async () => {
          await broadcastBlob(sessionRef.current!.myRound3Blob!);
          setRoundBlobSent(true);
        })();
      }
    } catch (err) {
      setBlobError(err instanceof Error ? err.message : 'Round 3 failed');
    }
  }, [relayClient, broadcastBlob]);

  // Combine
  const doCombine = useCallback(() => {
    if (!sessionRef.current) return;
    try {
      const sig = combine(sessionRef.current);
      if (sig) {
        setSession({ ...sessionRef.current });
        setPhase('complete');
        onSignatureReady(sig);
      } else {
        setBlobError('All iterations failed norm checks (randomness). Retry from round 1.');
        setPhase('failed');
      }
    } catch (err) {
      setBlobError(err instanceof Error ? err.message : 'Combine failed');
      setPhase('failed');
    }
  }, [onSignatureReady]);

  // Retry after failed combine
  const handleRetry = useCallback(() => {
    if (sessionRef.current) {
      destroySession(sessionRef.current);
    }
    sessionRef.current = null;
    setSession(null);
    setPhase('idle');
    setBlobError('');
    setBarriers({});
    barrierSentRef.current = {};
    relayInitRef.current = false; // allow relay re-init on retry
  }, []);

  // Cancel with cleanup
  const handleCancel = useCallback(() => {
    if (sessionRef.current) {
      destroySession(sessionRef.current);
    }
    sessionRef.current = null;
    onCancel();
  }, [onCancel]);

  // ---------------------------------------------------------------------------
  // Relay: auto-initialize signing when relayClient is provided
  // ---------------------------------------------------------------------------
  useEffect(() => {
    if (!relayClient || !relayClient.isReady || relayInitRef.current) return;
    if (phase !== 'idle') return;

    // Derive active party IDs from relay's parties map
    const ids = [...relayClient.parties.keys()].sort((a, b) => a - b);
    if (ids.length < share.threshold) return; // not enough parties yet

    // Take exactly T parties (the relay should have exactly T connected)
    const activeIds = ids.slice(0, share.threshold);

    relayInitRef.current = true;
    startSigningWithIds(activeIds);
  }, [relayClient, phase, share.threshold, startSigningWithIds]);

  // ---------------------------------------------------------------------------
  // Relay: subscribe to incoming messages and feed into addBlob
  // ---------------------------------------------------------------------------
  useEffect(() => {
    if (!relayClient) return;
    const handler = (_from: number, payload: Uint8Array) => {
      const text = new TextDecoder().decode(payload);

      // Intercept barrier messages
      const m = text.match(/^BARRIER:(\w+):(\d+)$/);
      if (m) {
        const barrierPhase = m[1]!;
        const pid = parseInt(m[2]!, 10);
        setBarriers(prev => {
          const next = { ...prev };
          const s = new Set(prev[barrierPhase]);
          s.add(pid);
          next[barrierPhase] = s;
          return next;
        });
        return;
      }

      if (!sessionRef.current) return;
      const result = addBlob(sessionRef.current, text);
      if (result.ok) {
        setSession({ ...sessionRef.current });
      }
      // Silently ignore invalid/duplicate blobs in relay mode
    };
    relayClient.on('message', handler);
    return () => { relayClient.off('message', handler); };
  }, [relayClient]);

  // ---------------------------------------------------------------------------
  // Relay: barrier sync — broadcast barrier when own blob sent + all collected
  // ---------------------------------------------------------------------------

  // Round 1: send barrier when ready
  useEffect(() => {
    if (!relayClient || phase !== 'round1' || !sessionRef.current) return;
    if (!roundBlobSent) return;
    const needed = sessionRef.current.activePartyIds.length;
    if (sessionRef.current.collectedRound1Hashes.size >= needed && !barrierSentRef.current.round1) {
      barrierSentRef.current.round1 = true;
      void broadcastBlob(`BARRIER:round1:${share.partyId}`);
      setBarriers(prev => {
        const s = new Set(prev.round1); s.add(share.partyId);
        return { ...prev, round1: s };
      });
    }
  }, [relayClient, phase, session, roundBlobSent, share.partyId, broadcastBlob]);

  // Round 1: advance when all barriers received
  useEffect(() => {
    if (!relayClient || phase !== 'round1' || !sessionRef.current) return;
    const needed = sessionRef.current.activePartyIds.length;
    if ((barriers.round1?.size ?? 0) >= needed) {
      advanceToRound2();
    }
  }, [relayClient, phase, barriers, advanceToRound2]);

  // Round 2: send barrier when ready
  useEffect(() => {
    if (!relayClient || phase !== 'round2' || !sessionRef.current) return;
    if (!roundBlobSent) return;
    const needed = sessionRef.current.activePartyIds.length;
    if (sessionRef.current.collectedRound2Commitments.size >= needed && !barrierSentRef.current.round2) {
      barrierSentRef.current.round2 = true;
      void broadcastBlob(`BARRIER:round2:${share.partyId}`);
      setBarriers(prev => {
        const s = new Set(prev.round2); s.add(share.partyId);
        return { ...prev, round2: s };
      });
    }
  }, [relayClient, phase, session, roundBlobSent, share.partyId, broadcastBlob]);

  // Round 2: advance when all barriers received
  useEffect(() => {
    if (!relayClient || phase !== 'round2' || !sessionRef.current) return;
    const needed = sessionRef.current.activePartyIds.length;
    if ((barriers.round2?.size ?? 0) >= needed) {
      advanceToRound3();
    }
  }, [relayClient, phase, barriers, advanceToRound3]);

  // Round 3: send barrier when ready
  useEffect(() => {
    if (!relayClient || phase !== 'round3' || !sessionRef.current) return;
    if (!roundBlobSent) return;
    const needed = sessionRef.current.activePartyIds.length;
    if (sessionRef.current.collectedRound3Responses.size >= needed && !barrierSentRef.current.round3) {
      barrierSentRef.current.round3 = true;
      void broadcastBlob(`BARRIER:round3:${share.partyId}`);
      setBarriers(prev => {
        const s = new Set(prev.round3); s.add(share.partyId);
        return { ...prev, round3: s };
      });
    }
  }, [relayClient, phase, session, roundBlobSent, share.partyId, broadcastBlob]);

  // Round 3: advance when all barriers received
  useEffect(() => {
    if (!relayClient || phase !== 'round3' || !sessionRef.current) return;
    const needed = sessionRef.current.activePartyIds.length;
    if ((barriers.round3?.size ?? 0) >= needed) {
      doCombine();
    }
  }, [relayClient, phase, barriers, doCombine]);

  const needed = share.threshold;

  // Build default party IDs string — show only the first T parties as example
  const defaultPartyIds = share.threshold === share.parties
    ? Array.from({ length: share.parties }, (_, i) => i).join(', ')
    : Array.from({ length: share.threshold }, (_, i) => i).join(', ');
  const parsedIds = parsePartyIds();
  const canStartSigning = !!parsedIds && parsedIds.length === share.threshold;

  // ---------------------------------------------------------------------------
  // Relay progress UI helper
  // ---------------------------------------------------------------------------
  const renderRelayProgress = (
    roundNumber: number,
    collected: Map<number, unknown>,
  ) => {
    const collectedCount = collected.size;
    return (
      <div className="threshold-blob-exchange">
        <div className="threshold-section-title">Round {roundNumber}</div>
        <PartyTracker activePartyIds={activePartyIds} collected={collected} selfId={share.partyId} />
        <div className="threshold-hint" style={{ textAlign: 'center', padding: '8px 0' }}>
          {collectedCount}/{needed} blobs received via relay
          {collectedCount < needed ? ' — waiting for peers...' : ' — advancing...'}
        </div>
        {blobError && (
          <div className="step-status error">{blobError}</div>
        )}
      </div>
    );
  };

  return (
    <div className="threshold-sign">
      <TxDetail
        stepTitle={stepTitle}
        targetContract={targetContract}
        params={txParams}
      />

      {phase === 'idle' && !relayClient && (
        <div className="threshold-idle">
          <p className="threshold-hint">
            This step requires {share.threshold}-of-{share.parties} threshold
            signing. You are Party {share.partyId}. Choose exactly{' '}
            {share.threshold} parties to participate (including yourself).
          </p>
          <div className="step-field" style={{ marginBottom: 12 }}>
            <label>Active signer party IDs (comma-separated, exactly {share.threshold} required)</label>
            <input
              type="text"
              placeholder={defaultPartyIds}
              value={partyInput}
              onChange={(e) => setPartyInput(e.target.value)}
            />
          </div>
          <div className="threshold-btn-row">
            <button
              className="step-execute-btn threshold-btn-half"
              onClick={startSigning}
              disabled={!canStartSigning}
            >
              Start Signing
            </button>
            <button
              className="step-execute-btn threshold-btn-half threshold-btn-cancel"
              onClick={handleCancel}
            >
              Cancel
            </button>
          </div>
        </div>
      )}

      {phase === 'idle' && relayClient && (
        <div className="threshold-idle">
          <div className="threshold-hint" style={{ textAlign: 'center', padding: '8px 0' }}>
            Waiting for relay to be ready...
          </div>
        </div>
      )}

      {phase === 'round1' && session?.myRound1Blob && (
        relayClient ? (
          renderRelayProgress(1, session.collectedRound1Hashes)
        ) : (
          <BlobExchange
            roundNumber={1}
            myBlob={session.myRound1Blob}
            threshold={needed}
            collected={session.collectedRound1Hashes}
            activePartyIds={activePartyIds}
            selfId={share.partyId}
            onAddBlob={handleAddBlob}
            onProceed={advanceToRound2}
            canProceed={session.collectedRound1Hashes.size >= needed}
            error={blobError}
          />
        )
      )}

      {phase === 'round2' && session?.myRound2Blob && (
        relayClient ? (
          renderRelayProgress(2, session.collectedRound2Commitments)
        ) : (
          <BlobExchange
            roundNumber={2}
            myBlob={session.myRound2Blob}
            threshold={needed}
            collected={session.collectedRound2Commitments}
            activePartyIds={activePartyIds}
            selfId={share.partyId}
            onAddBlob={handleAddBlob}
            onProceed={advanceToRound3}
            canProceed={session.collectedRound2Commitments.size >= needed}
            error={blobError}
          />
        )
      )}

      {phase === 'round3' && session?.myRound3Blob && (
        relayClient ? (
          renderRelayProgress(3, session.collectedRound3Responses)
        ) : (
          <BlobExchange
            roundNumber={3}
            myBlob={session.myRound3Blob}
            threshold={needed}
            collected={session.collectedRound3Responses}
            activePartyIds={activePartyIds}
            selfId={share.partyId}
            onAddBlob={handleAddBlob}
            onProceed={doCombine}
            canProceed={session.collectedRound3Responses.size >= needed}
            error={blobError}
          />
        )
      )}

      {phase === 'complete' && (
        <div className="threshold-complete">
          <div className="step-status confirmed">
            Signature combined successfully! Ready to broadcast.
          </div>
        </div>
      )}

      {phase === 'failed' && (
        <div className="threshold-complete">
          <div className="step-status error" style={{ cursor: 'default' }}>
            Signing attempt failed. Click Retry to start over.
          </div>
          {blobError && (
            <div className="step-status error" style={{ cursor: 'default', marginTop: 8, fontSize: 12, opacity: 0.85 }}>
              {blobError}
            </div>
          )}
          <div className="threshold-btn-row" style={{ marginTop: 12 }}>
            <button className="step-execute-btn threshold-btn-half" onClick={handleRetry}>
              Retry
            </button>
            <button className="step-execute-btn threshold-btn-half threshold-btn-cancel" onClick={handleCancel}>
              Cancel
            </button>
          </div>
        </div>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// ShareGate — wraps share import + threshold signing mode for Admin
// ---------------------------------------------------------------------------

interface ShareGateProps {
  children: (share: DecryptedShare) => React.ReactNode;
}

export function ShareGate({ children }: ShareGateProps) {
  const [share, setShare] = useState<DecryptedShare | null>(null);

  if (!share) {
    return <ShareImport onShareLoaded={setShare} />;
  }

  return (
    <div className="threshold-active">
      <div className="threshold-share-info">
        <span className="threshold-share-badge">
          Party {share.partyId} | {share.threshold}-of-{share.parties}
        </span>
        <button
          className="threshold-clear-btn"
          onClick={() => setShare(null)}
          title="Clear share and re-import"
        >
          Clear
        </button>
      </div>
      {children(share)}
    </div>
  );
}
