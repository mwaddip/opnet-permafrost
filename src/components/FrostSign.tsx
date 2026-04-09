import { useState, useCallback, useRef, useEffect } from 'react';
import {
  signRound1,
  signRound2,
  signAggregate,
  type KeyPackage,
  type PublicKeyPackage,
  type SigningCommitment,
  type SigningNonces,
  type SignatureShare,
  type Round1Output,
} from 'frots';
import {
  encodeFrostSignR1,
  decodeFrostSignR1,
  encodeFrostSignR2,
  decodeFrostSignR2,
  type SighashInfo,
  type FrostSignatureSet,
} from '../lib/frost-sign';
import { fromHex, toHex } from '../lib/hex';
import type { RelayClient } from '../lib/relay';

// ── Types ──

type FrostPhase = 'round1' | 'round2' | 'complete' | 'failed';

interface FrostSignProps {
  sighashes: SighashInfo[];
  frostKeyPackage: KeyPackage;
  frostPublicKey: string;          // hex, 33-byte SEC1 tweaked aggregate
  threshold: number;
  partyId: number;                 // 0-indexed
  onSignaturesReady: (sigs: FrostSignatureSet) => void;
  onCancel: () => void;
  relayClient?: RelayClient | null;
  relayReady?: boolean;
  isLeader?: boolean;
}

const FROST_STATE_PREFIX = 'FROST-STATE:';
const FROST_COMPLETE_PREFIX = 'FROST-COMPLETE:';

// ── Component ──

export function FrostSign({
  sighashes,
  frostKeyPackage,
  frostPublicKey,
  threshold,
  partyId,
  onSignaturesReady,
  onCancel,
  relayClient,
  relayReady,
  isLeader,
}: FrostSignProps) {
  void frostPublicKey; // available for future use (cheater detection)

  const [phase, setPhase] = useState<FrostPhase>('round1');
  const [error, setError] = useState('');

  // Per-sighash state
  const noncesRef = useRef<SigningNonces[]>([]);
  const myCommitmentsRef = useRef<SigningCommitment[]>([]);

  // Collected from peers: partyId → array of N commitments (one per sighash)
  const collectedR1Ref = useRef<Map<number, SigningCommitment[]>>(new Map());
  const [r1Count, setR1Count] = useState(0);

  // Collected partial sigs: partyId → array of N SignatureShares
  const collectedR2Ref = useRef<Map<number, SignatureShare[]>>(new Map());
  const [r2Count, setR2Count] = useState(0);

  // My round 2 partial sigs (for re-broadcasting)
  const mySharesRef = useRef<SignatureShare[]>([]);

  // State sync
  const blobsSentRef = useRef<Set<number>>(new Set());
  const peerStatesRef = useRef<Map<number, { round: number }>>(new Map());
  const initRef = useRef(false);

  // Session ID for blob envelope (use first sighash as session context)
  const sessionIdRef = useRef<Uint8Array>(
    sighashes.length > 0 ? fromHex(sighashes[0]!.hash) : new Uint8Array(32),
  );

  const N = sighashes.length;

  // ── Round 1: generate nonces + commitments ──
  const doRound1 = useCallback(() => {
    const rng = { fillBytes(dest: Uint8Array) { crypto.getRandomValues(dest); } };
    const nonces: SigningNonces[] = [];
    const commitments: SigningCommitment[] = [];

    for (let i = 0; i < N; i++) {
      const out: Round1Output = signRound1(frostKeyPackage, rng);
      nonces.push(out.nonces);
      commitments.push(out.commitments);
    }

    noncesRef.current = nonces;
    myCommitmentsRef.current = commitments;

    // Add own commitments to collected
    collectedR1Ref.current.set(partyId, commitments);
    setR1Count(1);

    // Broadcast
    if (relayClient) {
      const blob = encodeFrostSignR1(partyId, commitments, sessionIdRef.current);
      void relayClient.broadcast(new TextEncoder().encode(blob));
      blobsSentRef.current.add(1);
    }
  }, [N, frostKeyPackage, partyId, relayClient]);

  // ── Round 2: compute partial sigs ──
  const doRound2 = useCallback(() => {
    try {
      const shares: SignatureShare[] = [];

      for (let i = 0; i < N; i++) {
        const sighashBytes = fromHex(sighashes[i]!.hash);
        const tweaked = sighashes[i]!.type === 'key-path';

        // Gather all commitments for this sighash index
        const allCommitments: SigningCommitment[] = [];
        for (const [, peerCommitments] of collectedR1Ref.current) {
          allCommitments.push(peerCommitments[i]!);
        }

        const share = signRound2(
          frostKeyPackage,
          noncesRef.current[i]!,
          sighashBytes,
          allCommitments,
          { tweaked },
        );
        shares.push(share);
      }

      mySharesRef.current = shares;

      // Add own shares to collected
      collectedR2Ref.current.set(partyId, shares);
      setR2Count(1);
      setPhase('round2');

      // Broadcast
      if (relayClient) {
        const blob = encodeFrostSignR2(partyId, shares, sessionIdRef.current);
        void relayClient.broadcast(new TextEncoder().encode(blob));
        blobsSentRef.current.add(2);
      }
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Round 2 failed');
      setPhase('failed');
    }
  }, [N, sighashes, frostKeyPackage, partyId, relayClient]);

  // ── Aggregate (leader only) ──
  const doAggregate = useCallback(() => {
    try {
      // Build minimal PublicKeyPackage
      const pubKeyPkg: PublicKeyPackage = {
        verifyingKey: frostKeyPackage.verifyingKey,
        untweakedVerifyingKey: frostKeyPackage.untweakedVerifyingKey,
        verifyingShares: new Map(),
        untweakedVerifyingShares: new Map(),
        minSigners: threshold,
      };

      const signatures: Array<{ index: number; signature: string }> = [];

      for (let i = 0; i < N; i++) {
        const sighashBytes = fromHex(sighashes[i]!.hash);
        const tweaked = sighashes[i]!.type === 'key-path';

        // Gather all commitments for this sighash
        const allCommitments: SigningCommitment[] = [];
        for (const [, peerCommitments] of collectedR1Ref.current) {
          allCommitments.push(peerCommitments[i]!);
        }

        // Gather all partial sigs for this sighash
        const allShares: SignatureShare[] = [];
        for (const [, peerShares] of collectedR2Ref.current) {
          allShares.push(peerShares[i]!);
        }

        const sig = signAggregate(allShares, sighashBytes, allCommitments, pubKeyPkg, { tweaked });
        signatures.push({
          index: sighashes[i]!.index,
          signature: toHex(sig),
        });
      }

      const result: FrostSignatureSet = { signatures };
      setPhase('complete');

      // Broadcast completion to joiners
      if (relayClient) {
        void relayClient.broadcast(
          new TextEncoder().encode(FROST_COMPLETE_PREFIX + JSON.stringify(result.signatures)),
        );
      }

      onSignaturesReady(result);
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Aggregation failed');
      setPhase('failed');
    }
  }, [N, sighashes, frostKeyPackage, threshold, relayClient, onSignaturesReady]);

  // ── Auto-init round 1 ──
  useEffect(() => {
    if (initRef.current || !relayReady || N === 0) return;
    initRef.current = true;
    doRound1();
  }, [relayReady, N, doRound1]);

  // ── State sync: broadcast FROST-STATE periodically ──
  const broadcastState = useCallback(() => {
    if (!relayClient) return;
    const roundNum = phase === 'round1' ? 1 : phase === 'round2' ? 2 : phase === 'complete' ? 3 : 0;
    if (roundNum === 0) return;
    const sent = [...blobsSentRef.current].join(',');
    void relayClient.broadcast(
      new TextEncoder().encode(`${FROST_STATE_PREFIX}${partyId}:${roundNum}:${sent}`),
    );
  }, [relayClient, phase, partyId]);

  useEffect(() => { broadcastState(); }, [broadcastState, r1Count, r2Count]);

  useEffect(() => {
    if (!relayClient) return;
    const iv = setInterval(broadcastState, 500);
    return () => clearInterval(iv);
  }, [relayClient, broadcastState]);

  // ── Leader: auto-advance when all blobs collected ──
  const advancingRef = useRef(false);
  useEffect(() => {
    if (!isLeader || !relayClient || advancingRef.current) return;

    if (phase === 'round1' && r1Count >= threshold) {
      advancingRef.current = true;
      doRound2();
      advancingRef.current = false;
    } else if (phase === 'round2' && r2Count >= threshold) {
      advancingRef.current = true;
      doAggregate();
      advancingRef.current = false;
    }
  }, [isLeader, relayClient, phase, r1Count, r2Count, threshold, doRound2, doAggregate]);

  // ── Relay: handle incoming messages ──
  useEffect(() => {
    if (!relayClient) return;
    const handler = (_from: number, payload: Uint8Array) => {
      const text = new TextDecoder().decode(payload);

      // FROST-COMPLETE from leader
      if (text.startsWith(FROST_COMPLETE_PREFIX)) {
        try {
          const sigs = JSON.parse(text.slice(FROST_COMPLETE_PREFIX.length)) as Array<{ index: number; signature: string }>;
          setPhase('complete');
          onSignaturesReady({ signatures: sigs });
        } catch { /* ignore parse errors */ }
        return;
      }

      // FROST-STATE from peer
      const stateMatch = text.match(/^FROST-STATE:(\d+):(\d+):([\d,]*)$/);
      if (stateMatch) {
        const pid = parseInt(stateMatch[1]!, 10);
        const peerRound = parseInt(stateMatch[2]!, 10);
        peerStatesRef.current.set(pid, { round: peerRound });

        // Re-send blobs peer might need
        if (peerRound === 1 && blobsSentRef.current.has(1) && myCommitmentsRef.current.length > 0) {
          const blob = encodeFrostSignR1(partyId, myCommitmentsRef.current, sessionIdRef.current);
          void relayClient.broadcast(new TextEncoder().encode(blob));
        }
        if (peerRound === 2 && blobsSentRef.current.has(2) && mySharesRef.current.length > 0) {
          const blob = encodeFrostSignR2(partyId, mySharesRef.current, sessionIdRef.current);
          void relayClient.broadcast(new TextEncoder().encode(blob));
        }

        // Joiner: follow leader
        if (!isLeader) {
          const myRound = phase === 'round1' ? 1 : phase === 'round2' ? 2 : 3;
          if (peerRound > myRound && myRound === 1 && collectedR1Ref.current.size >= threshold) {
            doRound2();
          }
        }
        return;
      }

      // frost-sign-r1 blob
      const r1 = decodeFrostSignR1(text);
      if (r1 && r1.partyId !== partyId) {
        collectedR1Ref.current.set(r1.partyId, r1.commitments);
        setR1Count(collectedR1Ref.current.size);
        return;
      }

      // frost-sign-r2 blob
      const r2 = decodeFrostSignR2(text);
      if (r2 && r2.partyId !== partyId) {
        collectedR2Ref.current.set(r2.partyId, r2.shares);
        setR2Count(collectedR2Ref.current.size);
        return;
      }
    };

    relayClient.on('message', handler);
    return () => { relayClient.off('message', handler); };
  }, [relayClient, partyId, phase, isLeader, threshold, doRound2, onSignaturesReady]);

  // ── Render ──
  return (
    <div className="threshold-sign">
      <div className="threshold-section-title">FROST BTC Signing</div>

      {phase === 'round1' && (
        <div className="threshold-blob-exchange">
          <div className="threshold-section-title">Round 1 — Commitments</div>
          <div className="threshold-hint" style={{ textAlign: 'center', padding: '8px 0' }}>
            {r1Count}/{threshold} commitments received
            {r1Count < threshold ? ' — waiting for peers...' : ' — advancing...'}
          </div>
        </div>
      )}

      {phase === 'round2' && (
        <div className="threshold-blob-exchange">
          <div className="threshold-section-title">Round 2 — Partial Signatures</div>
          <div className="threshold-hint" style={{ textAlign: 'center', padding: '8px 0' }}>
            {r2Count}/{threshold} partial signatures received
            {r2Count < threshold ? ' — waiting for peers...' : ' — aggregating...'}
          </div>
        </div>
      )}

      {phase === 'complete' && (
        <div className="threshold-complete">
          <div className="step-status confirmed">
            FROST BTC signatures ready ({N} input{N !== 1 ? 's' : ''} signed)
          </div>
        </div>
      )}

      {phase === 'failed' && (
        <div className="threshold-complete">
          <div className="step-status error">{error || 'FROST signing failed'}</div>
          <button className="step-execute-btn" onClick={onCancel} style={{ marginTop: 12 }}>
            Cancel
          </button>
        </div>
      )}
    </div>
  );
}
