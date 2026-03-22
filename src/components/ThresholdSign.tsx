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

export function ShareImport({ onShareLoaded }: ShareImportProps) {
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  const [fileName, setFileName] = useState('');
  const fileRef = useRef<ShareFile | null>(null);
  const passwordRef = useRef<HTMLInputElement>(null);

  const handleFile = useCallback((e: React.ChangeEvent<HTMLInputElement>) => {
    setError('');
    const file = e.target.files?.[0];
    if (!file) return;
    setFileName(file.name);

    const reader = new FileReader();
    reader.onload = () => {
      try {
        fileRef.current = JSON.parse(reader.result as string) as ShareFile;
        setTimeout(() => passwordRef.current?.focus(), 50);
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
        Load your encrypted share file and enter your password to
        unlock it. The share is held in memory only.
      </p>

      <div className="step-field">
        <label title="Your encrypted DKG share file (.json) downloaded after the key generation ceremony">Share File (.json)</label>
        <input type="file" accept=".json" onChange={handleFile} />
        {fileName && <span className="threshold-filename">{fileName}</span>}
      </div>

      <div className="step-field">
        <label>Password</label>
        <input
          ref={passwordRef}
          autoFocus
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
  /** Whether the relay client is ready (React state — triggers re-render when relay becomes ready). */
  relayReady?: boolean;
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
  relayReady: relayReadyProp,
  relayPartyId: _relayPartyId,
}: ThresholdSignProps) {
  void _relayPartyId; // passed by caller but unused — signing uses share.partyId
  const [phase, setPhase] = useState<SigningPhase>('idle');
  const [session, setSession] = useState<SigningSession | null>(null);
  const [blobError, setBlobError] = useState('');
  const [activePartyIds, setActivePartyIds] = useState<number[]>([]);
  const [partyInput, setPartyInput] = useState('');

  // Session ref — intentionally no unmount cleanup here because StrictMode's
  // double-mount cycle would destroy round1State/round2State while the session
  // is still active. Session is destroyed explicitly in handleCancel/handleRetry.
  const sessionRef = useRef<SigningSession | null>(null);

  // Ref to track whether auto-init has fired (prevent double-start)
  const relayInitRef = useRef(false);
  const autoStartRef = useRef(false);

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

  // Pre-signing barrier: all parties must exchange SIGNING_READY before any
  // round 1 blobs are broadcast. This prevents the race where the initiator
  // sends its blob before joiner ThresholdSign components have mounted.
  const [signingReadyPeers, setSigningReadyPeers] = useState<Set<number>>(new Set());
  const signingReadySentRef = useRef(false);
  const round1BlobRef = useRef<string | null>(null);

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

    if (relayClient) {
      // Relay mode: store the blob — it will be broadcast after SIGNING_READY barrier
      round1BlobRef.current = blob;
    }
  }, [message, share, relayClient]);

  // Auto-start signing when threshold === parties (all parties must participate, no choice)
  useEffect(() => {
    if (autoStartRef.current || relayClient || phase !== 'idle') return;
    if (share.threshold !== share.parties) return;
    autoStartRef.current = true;
    const ids = Array.from({ length: share.parties }, (_, i) => i);
    startSigningWithIds(ids);
  }, [share.threshold, share.parties, relayClient, phase, startSigningWithIds]);

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

  // Combine — auto-retry in relay mode by restarting from round 1
  const combineAttemptRef = useRef(0);
  const MAX_COMBINE_ATTEMPTS = 50;

  const doCombine = useCallback(() => {
    if (!sessionRef.current) return;
    try {
      const sig = combine(sessionRef.current);
      if (sig) {
        combineAttemptRef.current = 0;
        setSession({ ...sessionRef.current });
        setPhase('complete');
        onSignatureReady(sig);
      } else {
        combineAttemptRef.current++;
        if (relayClient && combineAttemptRef.current < MAX_COMBINE_ATTEMPTS) {
          // Auto-retry: reset round state and restart from round 1
          setBlobError(`Norm check failed (attempt ${combineAttemptRef.current}/${MAX_COMBINE_ATTEMPTS}), retrying with fresh randomness...`);
          const s = sessionRef.current;
          s.round1State?.destroy();
          s.round2State?.destroy();
          s.round1State = null;
          s.round2State = null;
          s.myRound1Hash = null;
          s.myRound2Commitment = null;
          s.myRound3Response = null;
          s.collectedRound1Hashes.clear();
          s.collectedRound2Commitments.clear();
          s.collectedRound3Responses.clear();
          s.myRound1Blob = null;
          s.myRound2Blob = null;
          s.myRound3Blob = null;
          // Clear barriers so auto-advance re-evaluates
          setBarriers({});
          barrierSentRef.current = {};
          setPhase('round1');
          // Relay mode: restart from round 1
          const blob = round1(s);
          setSession({ ...s });
          void broadcastBlob(blob);
        } else {
          setBlobError(`Signing failed after ${combineAttemptRef.current} attempts. Click Retry to start over.`);
          setPhase('failed');
          combineAttemptRef.current = 0;
        }
      }
    } catch (err) {
      setBlobError(err instanceof Error ? err.message : 'Combine failed');
      setPhase('failed');
      combineAttemptRef.current = 0;
    }
  }, [onSignatureReady, relayClient, broadcastBlob]);

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
    if (!relayClient || !relayReadyProp || relayInitRef.current) return;
    if (phase !== 'idle') return;

    // Derive active party IDs from relay's parties map
    const ids = [...relayClient.parties.keys()].sort((a, b) => a - b);
    if (ids.length < share.threshold) return; // not enough parties yet

    // Take exactly T parties (the relay should have exactly T connected)
    const activeIds = ids.slice(0, share.threshold);

    relayInitRef.current = true;
    startSigningWithIds(activeIds);
  }, [relayClient, relayReadyProp, phase, share.threshold, startSigningWithIds]);

  // ---------------------------------------------------------------------------
  // Relay: broadcast SIGNING_READY when round1 starts
  // ---------------------------------------------------------------------------
  useEffect(() => {
    if (!relayClient || phase !== 'round1' || signingReadySentRef.current) return;
    signingReadySentRef.current = true;
    void broadcastBlob(`SIGNING_READY:${share.partyId}`);
    setSigningReadyPeers(prev => new Set(prev).add(share.partyId));
  }, [relayClient, phase, share.partyId, broadcastBlob]);

  // ---------------------------------------------------------------------------
  // Relay: broadcast round 1 blob once all parties are SIGNING_READY
  // ---------------------------------------------------------------------------
  useEffect(() => {
    if (!relayClient || phase !== 'round1') return;
    if (signingReadyPeers.size < activePartyIds.length) return;
    if (!round1BlobRef.current || roundBlobSent) return;

    const blob = round1BlobRef.current;
    round1BlobRef.current = null;
    void (async () => {
      const blobBytes = new TextEncoder().encode(blob);
      await relayClient.broadcast(blobBytes);
      setRoundBlobSent(true);
    })();
  }, [relayClient, phase, signingReadyPeers, activePartyIds.length, roundBlobSent]);

  // ---------------------------------------------------------------------------
  // Relay: subscribe to incoming messages and feed into addBlob
  // ---------------------------------------------------------------------------
  useEffect(() => {
    if (!relayClient) return;
    const handler = (from: number, payload: Uint8Array) => {
      const text = new TextDecoder().decode(payload);
      console.log(`[relay] msg from=${from} len=${text.length} preview=${text.slice(0, 40)}`);

      // Intercept SIGNING_READY messages (pre-signing barrier)
      const readyMatch = text.match(/^SIGNING_READY:(\d+)$/);
      if (readyMatch) {
        const pid = parseInt(readyMatch[1]!, 10);
        console.log(`[relay] SIGNING_READY from party ${pid}`);
        setSigningReadyPeers(prev => new Set(prev).add(pid));
        return;
      }

      // Intercept barrier messages
      const m = text.match(/^BARRIER:(\w+):(\d+)$/);
      if (m) {
        const barrierPhase = m[1]!;
        const pid = parseInt(m[2]!, 10);
        console.log(`[relay] BARRIER ${barrierPhase} from party ${pid}`);
        setBarriers(prev => {
          const next = { ...prev };
          const s = new Set(prev[barrierPhase]);
          s.add(pid);
          next[barrierPhase] = s;
          return next;
        });
        return;
      }

      if (!sessionRef.current) {
        console.warn('[relay] blob arrived but session is null — dropped');
        return;
      }
      const result = addBlob(sessionRef.current, text);
      if (result.ok) {
        console.log('[relay] addBlob accepted from party', from);
        setSession({ ...sessionRef.current });
      } else {
        console.warn('[relay] addBlob rejected:', result.error, 'blob preview:', text.slice(0, 50));
      }
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
          <div className="step-status error" title="This is normal — the ML-DSA threshold protocol is probabilistic. The system automatically retries with fresh randomness.">{blobError}</div>
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

      {phase === 'idle' && !relayClient && share.threshold < share.parties && (
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

