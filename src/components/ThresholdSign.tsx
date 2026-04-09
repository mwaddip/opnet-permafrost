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
  /** Whether this party is the session leader (created the session, drives round advancement). */
  isLeader?: boolean;
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
  isLeader,
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

  // ---------------------------------------------------------------------------
  // State-sync protocol: each party broadcasts its state every 2s.
  // Peers derive what's needed from each other's state and re-send on request.
  // Replaces SIGNING_READY, BARRIER, and NEED_BLOB with one mechanism.
  // ---------------------------------------------------------------------------
  const peerStatesRef = useRef<Map<number, { round: number; blobsSent: number[] }>>(new Map());
  const blobsSentRef = useRef<Set<number>>(new Set());

  // Start signing (shared between manual and relay modes)
  const startSigningWithIds = useCallback((ids: number[]) => {
    setActivePartyIds(ids);
    const sess = createSession(message, share, ids);
    round1(sess);
    sessionRef.current = sess;
    setSession({ ...sess });
    setPhase('round1');
    blobsSentRef.current = new Set();
    peerStatesRef.current = new Map();

    // Relay mode: immediately broadcast round 1 blob
    if (relayClient && sess.myRound1Blob) {
      void broadcastBlob(sess.myRound1Blob);
      blobsSentRef.current.add(1);
    }
  }, [message, share, relayClient, broadcastBlob]);

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

  // Shared restart-from-round-1 logic for auto-retry (leader only, relay mode)
  const retryAttemptRef = useRef(0);
  const MAX_RETRY_ATTEMPTS = 50;

  const restartFromRound1 = useCallback((reason: string) => {
    if (!sessionRef.current || !relayClient || !isLeader) return false;
    retryAttemptRef.current++;
    if (retryAttemptRef.current >= MAX_RETRY_ATTEMPTS) {
      setBlobError(`Signing failed after ${retryAttemptRef.current} attempts. Click Retry to start over.`);
      setPhase('failed');
      retryAttemptRef.current = 0;
      return false;
    }
    setBlobError(`${reason} (attempt ${retryAttemptRef.current}/${MAX_RETRY_ATTEMPTS}), retrying...`);
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
    blobsSentRef.current = new Set();
    peerStatesRef.current = new Map();
    setPhase('round1');
    round1(s);
    setSession({ ...s });
    if (s.myRound1Blob) {
      void broadcastBlob(s.myRound1Blob);
      blobsSentRef.current.add(1);
    }
    return true;
  }, [relayClient, isLeader, broadcastBlob]);

  // Advance to round 2
  const advanceToRound2 = useCallback(() => {
    if (!sessionRef.current) return;
    try {
      round2(sessionRef.current);
      setSession({ ...sessionRef.current });
      setPhase('round2');
      setBlobError('');

      if (relayClient && sessionRef.current.myRound2Blob) {
        void broadcastBlob(sessionRef.current.myRound2Blob);
        blobsSentRef.current.add(2);
      }
    } catch (err) {
      const msg = err instanceof Error ? err.message : 'Round 2 failed';
      if (!restartFromRound1(msg)) {
        setBlobError(msg);
      }
    }
  }, [relayClient, broadcastBlob, restartFromRound1]);

  // Advance to round 3
  const advanceToRound3 = useCallback(() => {
    if (!sessionRef.current) return;
    try {
      round3(sessionRef.current);
      setSession({ ...sessionRef.current });
      setPhase('round3');
      setBlobError('');

      if (relayClient && sessionRef.current.myRound3Blob) {
        void broadcastBlob(sessionRef.current.myRound3Blob);
        blobsSentRef.current.add(3);
      }
    } catch (err) {
      const msg = err instanceof Error ? err.message : 'Round 3 failed';
      if (!restartFromRound1(msg)) {
        setBlobError(msg);
      }
    }
  }, [relayClient, broadcastBlob, restartFromRound1]);

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
        // Leader: broadcast signature to joiners so they can complete too
        if (isLeader && relayClient) {
          const sigHex = Array.from(sig).map(b => b.toString(16).padStart(2, '0')).join('');
          void broadcastBlob(`COMPLETE:${sigHex}`);
        }
      } else {
        combineAttemptRef.current++;
        if (relayClient && isLeader && combineAttemptRef.current < MAX_COMBINE_ATTEMPTS) {
          // Leader auto-retry: reset and restart from round 1
          // Joiners will follow when they see our STATE go back to round 1
          setBlobError(`Norm check failed (attempt ${combineAttemptRef.current}/${MAX_COMBINE_ATTEMPTS}), retrying...`);
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
          blobsSentRef.current = new Set();
          peerStatesRef.current = new Map();
          setPhase('round1');
          round1(s);
          setSession({ ...s });
          if (s.myRound1Blob) {
            void broadcastBlob(s.myRound1Blob);
            blobsSentRef.current.add(1);
          }
        } else if (!isLeader && relayClient) {
          // Joiner: shouldn't reach here — leader sends COMPLETE
          setBlobError('Waiting for leader...');
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
    blobsSentRef.current = new Set();
    peerStatesRef.current = new Map();
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
  // Relay: leader-driven state-sync protocol
  //
  // The leader (session initiator) drives round advancement and combine.
  // Joiners follow — they advance when they see the leader is ahead.
  //
  // STATE:<partyId>:<round>:<blobsSent>
  // - Broadcast on every state change + every 500ms as fallback
  // - On receiving peer STATE: re-send blobs they might need
  // - Leader: advance when all blobs collected for current round
  // - Joiner: advance when leader's round is ahead of theirs
  // - Leader combine retry: resets to round 1, joiners follow when they
  //   see leader back on round 1
  // ---------------------------------------------------------------------------

  const phaseToRound = (p: string) =>
    p === 'round1' ? 1 : p === 'round2' ? 2 : p === 'round3' ? 3 : p === 'complete' ? 4 : 0;

  // Broadcast own state immediately
  const broadcastState = useCallback(() => {
    if (!relayClient) return;
    const roundNum = phaseToRound(phase);
    if (roundNum === 0) return;
    const sent = [...blobsSentRef.current].join(',');
    void relayClient.broadcast(
      new TextEncoder().encode(`STATE:${share.partyId}:${roundNum}:${sent}`)
    );
  }, [relayClient, phase, share.partyId]);

  // Broadcast state on every phase/session change (reactive)
  useEffect(() => {
    broadcastState();
  }, [broadcastState, session]);

  // Broadcast state periodically (fallback for dropped messages)
  useEffect(() => {
    if (!relayClient) return;
    const interval = setInterval(broadcastState, 500);
    return () => clearInterval(interval);
  }, [relayClient, broadcastState]);

  // Leader: reactive advance when all blobs are collected
  const advancingRef = useRef(false);
  useEffect(() => {
    if (!isLeader || !relayClient || !sessionRef.current || advancingRef.current) return;
    const roundNum = phaseToRound(phase);
    if (roundNum < 1 || roundNum > 3) return;

    const s = sessionRef.current;
    const needed = s.activePartyIds.length;
    const collected =
      roundNum === 1 ? s.collectedRound1Hashes.size :
      roundNum === 2 ? s.collectedRound2Commitments.size :
      roundNum === 3 ? s.collectedRound3Responses.size : 0;

    if (collected < needed) return;

    advancingRef.current = true;
    if (roundNum === 1) advanceToRound2();
    else if (roundNum === 2) advanceToRound3();
    else if (roundNum === 3) doCombine();
    advancingRef.current = false;
  }, [isLeader, relayClient, phase, session, advanceToRound2, advanceToRound3, doCombine]);

  // Relay: subscribe to incoming messages
  useEffect(() => {
    if (!relayClient) return;
    const handler = (_from: number, payload: Uint8Array) => {
      const text = new TextDecoder().decode(payload);

      // Handle COMPLETE message from leader — signing succeeded
      if (text.startsWith('COMPLETE:')) {
        const sigHex = text.slice(9);
        const sig = new Uint8Array(sigHex.match(/.{2}/g)!.map(b => parseInt(b, 16)));
        setPhase('complete');
        onSignatureReady(sig);
        return;
      }

      // Handle STATE messages from peers
      const stateMatch = text.match(/^STATE:(\d+):(\d+):([\d,]*)$/);
      if (stateMatch) {
        const pid = parseInt(stateMatch[1]!, 10);
        const peerRound = parseInt(stateMatch[2]!, 10);

        peerStatesRef.current.set(pid, { round: peerRound, blobsSent: stateMatch[3] ? stateMatch[3].split(',').map(Number) : [] });

        if (!sessionRef.current || !relayClient) return;
        const s = sessionRef.current;
        const myRound = phaseToRound(phase);

        // Re-send blobs the peer might need for their current round
        if (peerRound >= 1 && peerRound <= 3) {
          const blob = peerRound === 1 ? s.myRound1Blob : peerRound === 2 ? s.myRound2Blob : s.myRound3Blob;
          if (blob && blobsSentRef.current.has(peerRound)) {
            void relayClient.broadcast(new TextEncoder().encode(blob));
          }
        }

        // Joiner: follow the leader through rounds 1→2 and 2→3
        // (round 3→complete is handled by COMPLETE message, not combine)
        if (!isLeader && peerRound > myRound && myRound >= 1 && myRound <= 2) {
          const needed = s.activePartyIds.length;
          const collected =
            myRound === 1 ? s.collectedRound1Hashes.size :
            s.collectedRound2Commitments.size;
          if (collected >= needed) {
            if (myRound === 1) advanceToRound2();
            else if (myRound === 2) advanceToRound3();
          }
        }

        // Joiner: leader went back to round 1 (combine retry) — reset too
        if (!isLeader && peerRound === 1 && myRound > 1) {
          const s2 = sessionRef.current;
          s2.round1State?.destroy();
          s2.round2State?.destroy();
          s2.round1State = null;
          s2.round2State = null;
          s2.myRound1Hash = null;
          s2.myRound2Commitment = null;
          s2.myRound3Response = null;
          s2.collectedRound1Hashes.clear();
          s2.collectedRound2Commitments.clear();
          s2.collectedRound3Responses.clear();
          s2.myRound1Blob = null;
          s2.myRound2Blob = null;
          s2.myRound3Blob = null;
          blobsSentRef.current = new Set();
          setPhase('round1');
          round1(s2);
          setSession({ ...s2 });
          if (s2.myRound1Blob) {
            void broadcastBlob(s2.myRound1Blob);
            blobsSentRef.current.add(1);
          }
        }

        return;
      }

      // Handle signing blobs
      if (!sessionRef.current) return;
      const result = addBlob(sessionRef.current, text);
      if (result.ok) {
        setSession({ ...sessionRef.current });
      }
    };
    relayClient.on('message', handler);
    return () => { relayClient.off('message', handler); };
  }, [relayClient, phase, isLeader, advanceToRound2, advanceToRound3, doCombine, broadcastBlob]);

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

