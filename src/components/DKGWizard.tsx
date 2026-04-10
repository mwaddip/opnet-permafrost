/**
 * DKGWizard — 6-step distributed key generation ceremony.
 *
 * Join → Commit → Reveal → Masks → Aggregate → Complete
 *
 * Each party runs this independently in their own browser.
 * No single party ever sees another's secret share.
 *
 * Supports two transport modes:
 * - Offline: manual copy/paste of blobs between parties
 * - Relay: auto-send/receive via encrypted WebSocket relay
 */

import { useState, useReducer, useCallback, useRef, useEffect } from 'react';
import { PasswordModal } from './PasswordModal';
import { encryptShareV3, downloadShareFile, toHex } from '../lib/keygen';
import {
  createDKGInstance,
  generateSessionId,
  getSessionIdPrefix,
  sessionIdFromHex,
  getKL,
  encodeSessionConfig,
  decodeSessionConfig,
  encodePhase1Broadcast,
  decodePhase1Broadcast,
  encodePhase2Broadcast,
  decodePhase2Broadcast,
  encodePhase2Private,
  decodePhase2Private,
  encodePhase3Private,
  decodePhase3Private,
  encodePhase4Broadcast,
  decodePhase4Broadcast,
  encodeFrostRound1,
  decodeFrostRound1,
  encodeFrostRound2,
  decodeFrostRound2,
  partyIdToFrostId,
  frostIdToPartyId,
  identifyBlob,
  type DKGPhase1Broadcast,
  type DKGPhase1State,
  type DKGPhase2Broadcast,
  type DKGPhase2Private,
  type DKGPhase2FinalizeResult,
  type DKGPhase3Private,
  type DKGPhase4Broadcast,
  type FrostRound1Package,
  type FrostRound2Package,
  ThresholdMLDSA,
} from '../lib/dkg';
import {
  dkgRound1 as frostDkgRound1,
  dkgRound2 as frostDkgRound2,
  dkgFinalize as frostDkgFinalize,
  signRound1 as frostSignR1,
  signRound2 as frostSignR2,
  signAggregate as frostSignAgg,
  type Round1SecretPackage as FrostR1Secret,
  type Round2SecretPackage as FrostR2Secret,
  type KeyPackage as FrostKeyPackage,
  type PublicKeyPackage as FrostPublicKeyPackage,
  type SigningCommitment,
  type SigningNonces,
  type SignatureShare,
} from 'frots';
import { RelayClient } from '../lib/relay';
import { sessionFingerprint } from '../lib/relay-crypto';
import { RELAY_URL } from '../lib/api';
import type { ThresholdKeyShare } from '@btc-vision/post-quantum/threshold-ml-dsa.js';
import { OtziWordmark } from '../App';
import { computeKeyLinkHash } from '../lib/frost-link';
import { encodeFrostSignR1, decodeFrostSignR1, encodeFrostSignR2, decodeFrostSignR2 } from '../lib/frost-sign';

// ── Types ──

type Step = 'join' | 'commit' | 'reveal' | 'masks' | 'aggregate' | 'frost-commit' | 'frost-shares' | 'frost-link' | 'complete';
type Role = 'initiator' | 'joiner';
type TransportMode = 'choose' | 'offline' | 'relay-create' | 'relay-join';

interface DKGState {
  step: Step;
  role: Role;
  threshold: number;
  parties: number;
  level: number;
  sessionId: Uint8Array | null;
  myPartyId: number;
  instance: ThresholdMLDSA | null;

  // Phase 1
  phase1State: DKGPhase1State | null;
  myPhase1Blob: string | null;
  collectedPhase1: DKGPhase1Broadcast[];

  // Phase 2
  myPhase2PubBlob: string | null;
  myPhase2PrivBlobs: Map<number, string>;
  collectedPhase2Pub: DKGPhase2Broadcast[];
  collectedPhase2Priv: DKGPhase2Private[];

  // Phase 2 finalize + Phase 3
  phase2FinalResult: DKGPhase2FinalizeResult | null;
  myPhase3PrivBlobs: Map<number, string>;
  collectedPhase3Priv: DKGPhase3Private[];

  // Phase 4
  myPhase4Blob: string | null;
  collectedPhase4: DKGPhase4Broadcast[];

  // FROST DKG Round 1
  frostR1Secret: FrostR1Secret | null;
  myFrostR1Blob: string | null;
  collectedFrostR1: FrostRound1Package[];

  // FROST DKG Round 2
  frostR2Secret: FrostR2Secret | null;
  myFrostR2Blobs: Map<number, string>;
  collectedFrostR2: FrostRound2Package[];

  // FROST key-link signing
  frostLinkSig: string | null;  // 64-byte hex FROST Schnorr sig over key-link message

  // Result
  publicKey: Uint8Array | null;
  share: ThresholdKeyShare | null;
  frostKeyPackage: FrostKeyPackage | null;
  frostPublicKeyPackage: FrostPublicKeyPackage | null;

  // Bitmask setup
  bitmasks: readonly number[];
  holdersOf: ReadonlyMap<number, readonly number[]>;

  error: string | null;
}

type Action =
  | { type: 'SET_PARAMS'; threshold: number; parties: number; level: number }
  | { type: 'SET_ROLE'; role: Role }
  | { type: 'SET_PARTY_ID'; partyId: number }
  | { type: 'INIT_SESSION'; sessionId: Uint8Array; instance: ThresholdMLDSA; bitmasks: readonly number[]; holdersOf: ReadonlyMap<number, readonly number[]> }
  | { type: 'SET_STEP'; step: Step }
  | { type: 'SET_PHASE1'; state: DKGPhase1State; blob: string; ownBroadcast: DKGPhase1Broadcast }
  | { type: 'ADD_PHASE1'; broadcast: DKGPhase1Broadcast }
  | { type: 'SET_PHASE2'; pubBlob: string; privBlobs: Map<number, string>; ownPub: DKGPhase2Broadcast }
  | { type: 'ADD_PHASE2_PUB'; broadcast: DKGPhase2Broadcast }
  | { type: 'ADD_PHASE2_PRIV'; priv: DKGPhase2Private }
  | { type: 'SET_PHASE2_FINAL'; result: DKGPhase2FinalizeResult; privBlobs: Map<number, string> }
  | { type: 'ADD_PHASE3_PRIV'; priv: DKGPhase3Private }
  | { type: 'SET_PHASE4'; blob: string; ownBroadcast: DKGPhase4Broadcast }
  | { type: 'ADD_PHASE4'; broadcast: DKGPhase4Broadcast }
  | { type: 'SET_FROST_R1'; secret: FrostR1Secret; blob: string; ownPackage: FrostRound1Package }
  | { type: 'ADD_FROST_R1'; pkg: FrostRound1Package }
  | { type: 'SET_FROST_R2'; secret: FrostR2Secret; blobs: Map<number, string> }
  | { type: 'ADD_FROST_R2'; pkg: FrostRound2Package }
  | { type: 'SET_RESULT'; publicKey: Uint8Array; share: ThresholdKeyShare }
  | { type: 'SET_FROST_RESULT'; keyPackage: FrostKeyPackage; publicKeyPackage: FrostPublicKeyPackage }
  | { type: 'SET_FROST_LINK_SIG'; sig: string }
  | { type: 'SET_ERROR'; error: string | null };

const initialState: DKGState = {
  step: 'join',
  role: 'initiator',
  threshold: 3,
  parties: 5,
  level: 44,
  sessionId: null,
  myPartyId: 0,
  instance: null,
  phase1State: null,
  myPhase1Blob: null,
  collectedPhase1: [],
  myPhase2PubBlob: null,
  myPhase2PrivBlobs: new Map(),
  collectedPhase2Pub: [],
  collectedPhase2Priv: [],
  phase2FinalResult: null,
  myPhase3PrivBlobs: new Map(),
  collectedPhase3Priv: [],
  myPhase4Blob: null,
  collectedPhase4: [],
  frostR1Secret: null,
  myFrostR1Blob: null,
  collectedFrostR1: [],
  frostR2Secret: null,
  myFrostR2Blobs: new Map(),
  collectedFrostR2: [],
  frostLinkSig: null,
  publicKey: null,
  share: null,
  frostKeyPackage: null,
  frostPublicKeyPackage: null,
  bitmasks: [],
  holdersOf: new Map(),
  error: null,
};

function reducer(state: DKGState, action: Action): DKGState {
  switch (action.type) {
    case 'SET_PARAMS':
      return { ...state, threshold: action.threshold, parties: action.parties, level: action.level };
    case 'SET_ROLE':
      return { ...state, role: action.role };
    case 'SET_PARTY_ID':
      return { ...state, myPartyId: action.partyId };
    case 'INIT_SESSION':
      return { ...state, sessionId: action.sessionId, instance: action.instance, bitmasks: action.bitmasks, holdersOf: action.holdersOf };
    case 'SET_STEP':
      return { ...state, step: action.step, error: null };
    case 'SET_PHASE1': {
      // Preserve any blobs that arrived via relay before own generation
      const prior1 = state.collectedPhase1.filter(b => b.partyId !== action.ownBroadcast.partyId);
      return { ...state, phase1State: action.state, myPhase1Blob: action.blob, collectedPhase1: [action.ownBroadcast, ...prior1] };
    }
    case 'ADD_PHASE1': {
      if (state.collectedPhase1.some(b => b.partyId === action.broadcast.partyId)) return state;
      return { ...state, collectedPhase1: [...state.collectedPhase1, action.broadcast] };
    }
    case 'SET_PHASE2': {
      const prior2 = state.collectedPhase2Pub.filter(b => b.partyId !== action.ownPub.partyId);
      return { ...state, myPhase2PubBlob: action.pubBlob, myPhase2PrivBlobs: action.privBlobs, collectedPhase2Pub: [action.ownPub, ...prior2] };
    }
    case 'ADD_PHASE2_PUB': {
      if (state.collectedPhase2Pub.some(b => b.partyId === action.broadcast.partyId)) return state;
      return { ...state, collectedPhase2Pub: [...state.collectedPhase2Pub, action.broadcast] };
    }
    case 'ADD_PHASE2_PRIV': {
      if (state.collectedPhase2Priv.some(b => b.fromPartyId === action.priv.fromPartyId)) return state;
      return { ...state, collectedPhase2Priv: [...state.collectedPhase2Priv, action.priv] };
    }
    case 'SET_PHASE2_FINAL':
      return { ...state, phase2FinalResult: action.result, myPhase3PrivBlobs: action.privBlobs };
    case 'ADD_PHASE3_PRIV': {
      if (state.collectedPhase3Priv.some(b => b.fromGeneratorId === action.priv.fromGeneratorId)) return state;
      return { ...state, collectedPhase3Priv: [...state.collectedPhase3Priv, action.priv] };
    }
    case 'SET_PHASE4': {
      const prior4 = state.collectedPhase4.filter(b => b.partyId !== action.ownBroadcast.partyId);
      return { ...state, myPhase4Blob: action.blob, collectedPhase4: [action.ownBroadcast, ...prior4] };
    }
    case 'ADD_PHASE4': {
      if (state.collectedPhase4.some(b => b.partyId === action.broadcast.partyId)) return state;
      return { ...state, collectedPhase4: [...state.collectedPhase4, action.broadcast] };
    }
    case 'SET_FROST_R1': {
      const prior = state.collectedFrostR1.filter(p => p.identifier !== action.ownPackage.identifier);
      return { ...state, frostR1Secret: action.secret, myFrostR1Blob: action.blob, collectedFrostR1: [action.ownPackage, ...prior] };
    }
    case 'ADD_FROST_R1': {
      if (state.collectedFrostR1.some(p => p.identifier === action.pkg.identifier)) return state;
      return { ...state, collectedFrostR1: [...state.collectedFrostR1, action.pkg] };
    }
    case 'SET_FROST_R2':
      return { ...state, frostR2Secret: action.secret, myFrostR2Blobs: action.blobs };
    case 'ADD_FROST_R2': {
      if (state.collectedFrostR2.some(p => p.sender === action.pkg.sender)) return state;
      return { ...state, collectedFrostR2: [...state.collectedFrostR2, action.pkg] };
    }
    case 'SET_RESULT':
      return { ...state, publicKey: action.publicKey, share: action.share };
    case 'SET_FROST_RESULT':
      return { ...state, frostKeyPackage: action.keyPackage, frostPublicKeyPackage: action.publicKeyPackage };
    case 'SET_FROST_LINK_SIG':
      return { ...state, frostLinkSig: action.sig };
    case 'SET_ERROR':
      return { ...state, error: action.error };
  }
}

// ── Step labels and indices ──

const STEPS: Step[] = ['join', 'commit', 'reveal', 'masks', 'aggregate', 'frost-commit', 'frost-shares', 'frost-link', 'complete'];
const STEP_LABELS = ['Join', 'Commit', 'Reveal', 'Masks', 'Aggregate', 'FROST R1', 'FROST R2', 'Key Link', 'Complete'];

// ── Extracted sub-components (defined outside DKGWizard to avoid re-creation) ──

function PartyTracker({ collected, total, myPartyId, label }: {
  collected: number[];
  total: number;
  myPartyId: number;
  label: string;
}) {
  return (
    <div className="party-tracker">
      <span className="tracker-label">{label}:</span>
      {Array.from({ length: total }, (_, i) => (
        <span key={i} className={`tracker-dot ${collected.includes(i) ? 'collected' : ''} ${i === myPartyId ? 'self' : ''}`}>
          {i + 1}{collected.includes(i) ? ' \u2713' : ' \u25CB'}
        </span>
      ))}
    </div>
  );
}

function PasteArea({ value, onChange, onProcess }: {
  value: string;
  onChange: (v: string) => void;
  onProcess: (v: string) => void;
}) {
  return (
    <div style={{ marginTop: 16 }}>
      <textarea
        className="blob-textarea"
        placeholder="Paste a blob from another party here..."
        value={value}
        onChange={e => onChange(e.target.value)}
        rows={3}
      />
      <button
        className="btn btn-secondary btn-full"
        style={{ marginTop: 8 }}
        onClick={() => onProcess(value)}
        disabled={!value.trim()}
      >
        Process Blob
      </button>
    </div>
  );
}

function BlobOutput({ blob, label, isPrivate, targetParty, onCopy, copiedLabel }: {
  blob: string;
  label: string;
  isPrivate?: boolean;
  targetParty?: number;
  onCopy: (text: string, label: string) => void;
  copiedLabel: string | null;
}) {
  return (
    <div className={`blob-output-wrapper ${isPrivate ? 'private-blob-warning' : ''}`}>
      {isPrivate && targetParty !== undefined && (
        <div className="private-label">Private — share ONLY with Party {targetParty + 1}</div>
      )}
      <div className="blob-output-header">
        <span>{label}</span>
        <button
          className="btn-copy"
          onClick={() => onCopy(blob, label)}
        >
          {copiedLabel === label ? 'Copied!' : 'Copy'}
        </button>
      </div>
      <div className="blob-output">{blob}</div>
    </div>
  );
}

// ── Relay progress indicator ──

function RelayPhaseProgress({ phase, collected, total, label }: {
  phase: string;
  collected: number;
  total: number;
  label: string;
}) {
  return (
    <div style={{ textAlign: 'center', padding: '12px 0' }}>
      <div className="spinner" style={{ margin: '0 auto 12px', width: 24, height: 24 }} />
      <p style={{ fontSize: 14, color: 'var(--white-dim)' }}>
        {phase}: {label} ({collected}/{total})
      </p>
    </div>
  );
}

// ── Main component ──

interface DKGWizardProps {
  onComplete?: () => void;
  initialSessionCode?: string | null;
}

export function DKGWizard({ onComplete, initialSessionCode }: DKGWizardProps = {}) {
  const [state, dispatch] = useReducer(reducer, initialState);
  const [pasteValue, setPasteValue] = useState('');
  const [copied, setCopied] = useState<string | null>(null);
  const [showPasswordModal, setShowPasswordModal] = useState(false);
  const [hostingConfig, setHostingConfig] = useState<import('../lib/vault-types').HostingConfig | null>(null);

  useEffect(() => {
    import('../lib/api').then(({ getConfig }) =>
      getConfig().then(c => { if (c.hosting) setHostingConfig(c.hosting); }).catch(() => {})
    );
  }, []);

  // ── Transport mode state ──
  const [transportMode, setTransportMode] = useState<TransportMode>(
    initialSessionCode && initialSessionCode.length >= 6 ? 'relay-join' : 'choose',
  );
  const [relayClient, setRelayClient] = useState<RelayClient | null>(null);
  const relayClientRef = useRef<RelayClient | null>(null);
  const [relaySessionCode, setRelaySessionCode] = useState('');
  const [relaySessionUrl, setRelaySessionUrl] = useState('');
  const [relayJoinCode, setRelayJoinCode] = useState(initialSessionCode || '');
  const [relayStatus, setRelayStatus] = useState('');
  const [relayError, setRelayError] = useState('');
  const [relayReady, setRelayReady] = useState(false);
  const [relayFingerprint, setRelayFingerprint] = useState('');
  const [relayPartyCount, setRelayPartyCount] = useState(0);
  const [relayPartyTotal, setRelayPartyTotal] = useState(0);

  const isRelayMode = transportMode === 'relay-create' || transportMode === 'relay-join';

  // Relay send completion flags (state, not refs, so auto-advance re-evaluates)
  const [phase1Sent, setPhase1Sent] = useState(false);
  const [phase2Sent, setPhase2Sent] = useState(false);
  const [phase3Sent, setPhase3Sent] = useState(false);
  const [phase4Sent, setPhase4Sent] = useState(false);
  const [frostR1Sent, setFrostR1Sent] = useState(false);
  const [frostR2Sent, setFrostR2Sent] = useState(false);

  // FROST key-link signing state (refs for intermediate, state for counts to trigger re-renders)
  const flinkNoncesRef = useRef<SigningNonces | null>(null);
  const flinkCommitmentsRef = useRef<Map<number, SigningCommitment>>(new Map());
  const flinkSharesRef = useRef<Map<number, SignatureShare>>(new Map());
  const [flinkR1Count, setFlinkR1Count] = useState(0);
  const [flinkR2Count, setFlinkR2Count] = useState(0);
  const flinkInitRef = useRef(false);
  const flinkR2DoneRef = useRef(false);
  const flinkHashRef = useRef<Uint8Array | null>(null);

  // Barrier synchronisation: parties don't advance until ALL parties confirm
  // they have sent their blob AND collected all expected blobs for the phase.
  // This prevents the race where Party A advances before Party B receives A's blob.
  const [barriers, setBarriers] = useState<Record<string, Set<number>>>({});
  const barrierSentRef = useRef<Record<string, boolean>>({});

  // Auto-join from URL ?session=XXXXXX
  useEffect(() => {
    const params = new URLSearchParams(window.location.search);
    const sessionParam = params.get('session');
    if (sessionParam && sessionParam.trim().length === 6) {
      setTransportMode('relay-join');
      setRelayJoinCode(sessionParam.trim().toUpperCase());
    }
  }, []);

  const stepIndex = STEPS.indexOf(state.step);

  // Cleanup relay on unmount
  useEffect(() => {
    return () => {
      if (relayClientRef.current) {
        relayClientRef.current.close();
        relayClientRef.current = null;
      }
    };
  }, []);

  // ── Copy helper ──
  const copyToClipboard = useCallback((text: string, label: string) => {
    navigator.clipboard.writeText(text).then(
      () => { setCopied(label); setTimeout(() => setCopied(null), 2000); },
      () => dispatch({ type: 'SET_ERROR', error: 'Failed to copy to clipboard' }),
    );
  }, []);


  // ── Session ID prefix for validation ──
  const sidPrefix = state.sessionId ? getSessionIdPrefix(state.sessionId) : '';

  // ── Smart paste handler (used by both offline paste and relay receive) ──
  const handlePaste = useCallback((text: string) => {
    if (!text.trim()) return;
    dispatch({ type: 'SET_ERROR', error: null });
    const info = identifyBlob(text.trim());
    if (!info) {
      dispatch({ type: 'SET_ERROR', error: 'Invalid blob format' });
      return;
    }
    // Validate session ID
    if (sidPrefix && info.sid !== sidPrefix) {
      dispatch({ type: 'SET_ERROR', error: `Wrong session (expected ${sidPrefix.slice(0, 8)}..., got ${info.sid.slice(0, 8)}...)` });
      return;
    }
    // Reject self-blobs
    if (info.from === state.myPartyId && info.type !== 'session') {
      dispatch({ type: 'SET_ERROR', error: 'This is your own blob — paste blobs from other parties' });
      return;
    }
    // Reject blobs addressed to someone else
    if (info.to !== -1 && info.to !== state.myPartyId) {
      dispatch({ type: 'SET_ERROR', error: `This blob is addressed to Party ${info.to + 1}, not you` });
      return;
    }

    // Route by type
    switch (info.type) {
      case 'p1': {
        const broadcast = decodePhase1Broadcast(text.trim());
        if (!broadcast) { dispatch({ type: 'SET_ERROR', error: 'Failed to decode Phase 1 blob' }); return; }
        if (state.collectedPhase1.some(b => b.partyId === broadcast.partyId)) {
          dispatch({ type: 'SET_ERROR', error: `Already have Phase 1 from Party ${broadcast.partyId + 1}` });
          return;
        }
        dispatch({ type: 'ADD_PHASE1', broadcast });
        break;
      }
      case 'p2pub': {
        const broadcast = decodePhase2Broadcast(text.trim());
        if (!broadcast) { dispatch({ type: 'SET_ERROR', error: 'Failed to decode Phase 2 public blob' }); return; }
        if (state.collectedPhase2Pub.some(b => b.partyId === broadcast.partyId)) {
          dispatch({ type: 'SET_ERROR', error: `Already have Phase 2 public from Party ${broadcast.partyId + 1}` });
          return;
        }
        dispatch({ type: 'ADD_PHASE2_PUB', broadcast });
        break;
      }
      case 'p2priv': {
        const priv = decodePhase2Private(text.trim());
        if (!priv) { dispatch({ type: 'SET_ERROR', error: 'Failed to decode Phase 2 private blob' }); return; }
        if (state.collectedPhase2Priv.some(b => b.fromPartyId === priv.fromPartyId)) {
          dispatch({ type: 'SET_ERROR', error: `Already have Phase 2 private from Party ${priv.fromPartyId + 1}` });
          return;
        }
        dispatch({ type: 'ADD_PHASE2_PRIV', priv });
        break;
      }
      case 'p3priv': {
        const priv = decodePhase3Private(text.trim());
        if (!priv) { dispatch({ type: 'SET_ERROR', error: 'Failed to decode Phase 3 blob' }); return; }
        if (state.collectedPhase3Priv.some(b => b.fromGeneratorId === priv.fromGeneratorId)) {
          dispatch({ type: 'SET_ERROR', error: `Already have Phase 3 from generator ${priv.fromGeneratorId + 1}` });
          return;
        }
        dispatch({ type: 'ADD_PHASE3_PRIV', priv });
        break;
      }
      case 'p4': {
        const broadcast = decodePhase4Broadcast(text.trim());
        if (!broadcast) { dispatch({ type: 'SET_ERROR', error: 'Failed to decode Phase 4 blob' }); return; }
        if (state.collectedPhase4.some(b => b.partyId === broadcast.partyId)) {
          dispatch({ type: 'SET_ERROR', error: `Already have Phase 4 from Party ${broadcast.partyId + 1}` });
          return;
        }
        dispatch({ type: 'ADD_PHASE4', broadcast });
        break;
      }
      case 'frost-r1': {
        const pkg = decodeFrostRound1(text.trim());
        if (!pkg) { dispatch({ type: 'SET_ERROR', error: 'Failed to decode FROST Round 1 blob' }); return; }
        if (state.collectedFrostR1.some(p => p.identifier === pkg.identifier)) {
          dispatch({ type: 'SET_ERROR', error: `Already have FROST R1 from Party ${frostIdToPartyId(pkg.identifier) + 1}` });
          return;
        }
        dispatch({ type: 'ADD_FROST_R1', pkg });
        break;
      }
      case 'frost-r2': {
        const pkg = decodeFrostRound2(text.trim());
        if (!pkg) { dispatch({ type: 'SET_ERROR', error: 'Failed to decode FROST Round 2 blob' }); return; }
        if (state.collectedFrostR2.some(p => p.sender === pkg.sender)) {
          dispatch({ type: 'SET_ERROR', error: `Already have FROST R2 from Party ${frostIdToPartyId(pkg.sender) + 1}` });
          return;
        }
        dispatch({ type: 'ADD_FROST_R2', pkg });
        break;
      }
      default:
        dispatch({ type: 'SET_ERROR', error: `Unexpected blob type "${info.type}" for this step` });
    }
    setPasteValue('');
  }, [sidPrefix, state.myPartyId, state.collectedPhase1, state.collectedPhase2Pub, state.collectedPhase2Priv, state.collectedPhase3Priv, state.collectedPhase4, state.collectedFrostR1, state.collectedFrostR2]);

  // ── Silent paste handler for relay (no error dispatch, returns success boolean) ──
  const handleRelayBlob = useCallback((text: string): boolean => {
    if (!text.trim()) return false;
    const info = identifyBlob(text.trim());
    if (!info) return false;
    if (sidPrefix && info.sid !== sidPrefix) return false;
    if (info.from === state.myPartyId && info.type !== 'session') return false;
    if (info.to !== -1 && info.to !== state.myPartyId) return false;

    switch (info.type) {
      case 'p1': {
        const broadcast = decodePhase1Broadcast(text.trim());
        if (!broadcast) return false;
        if (state.collectedPhase1.some(b => b.partyId === broadcast.partyId)) return false;
        dispatch({ type: 'ADD_PHASE1', broadcast });
        return true;
      }
      case 'p2pub': {
        const broadcast = decodePhase2Broadcast(text.trim());
        if (!broadcast) return false;
        if (state.collectedPhase2Pub.some(b => b.partyId === broadcast.partyId)) return false;
        dispatch({ type: 'ADD_PHASE2_PUB', broadcast });
        return true;
      }
      case 'p2priv': {
        const priv = decodePhase2Private(text.trim());
        if (!priv) return false;
        if (state.collectedPhase2Priv.some(b => b.fromPartyId === priv.fromPartyId)) return false;
        dispatch({ type: 'ADD_PHASE2_PRIV', priv });
        return true;
      }
      case 'p3priv': {
        const priv = decodePhase3Private(text.trim());
        if (!priv) return false;
        if (state.collectedPhase3Priv.some(b => b.fromGeneratorId === priv.fromGeneratorId)) return false;
        dispatch({ type: 'ADD_PHASE3_PRIV', priv });
        return true;
      }
      case 'p4': {
        const broadcast = decodePhase4Broadcast(text.trim());
        if (!broadcast) return false;
        if (state.collectedPhase4.some(b => b.partyId === broadcast.partyId)) return false;
        dispatch({ type: 'ADD_PHASE4', broadcast });
        return true;
      }
      case 'frost-r1': {
        const pkg = decodeFrostRound1(text.trim());
        if (!pkg) return false;
        if (state.collectedFrostR1.some(p => p.identifier === pkg.identifier)) return false;
        dispatch({ type: 'ADD_FROST_R1', pkg });
        return true;
      }
      case 'frost-r2': {
        const pkg = decodeFrostRound2(text.trim());
        if (!pkg) return false;
        if (state.collectedFrostR2.some(p => p.sender === pkg.sender)) return false;
        dispatch({ type: 'ADD_FROST_R2', pkg });
        return true;
      }
      case 'frost-sign-r1': {
        const decoded = decodeFrostSignR1(text.trim());
        if (!decoded || decoded.partyId === state.myPartyId) return false;
        if (flinkCommitmentsRef.current.has(decoded.partyId)) return false;
        flinkCommitmentsRef.current.set(decoded.partyId, decoded.commitments[0]!);
        setFlinkR1Count(flinkCommitmentsRef.current.size);
        return true;
      }
      case 'frost-sign-r2': {
        const decoded = decodeFrostSignR2(text.trim());
        if (!decoded || decoded.partyId === state.myPartyId) return false;
        if (flinkSharesRef.current.has(decoded.partyId)) return false;
        flinkSharesRef.current.set(decoded.partyId, decoded.shares[0]!);
        setFlinkR2Count(flinkSharesRef.current.size);
        return true;
      }
      default:
        return false;
    }
  }, [sidPrefix, state.myPartyId, state.collectedPhase1, state.collectedPhase2Pub, state.collectedPhase2Priv, state.collectedPhase3Priv, state.collectedPhase4, state.collectedFrostR1, state.collectedFrostR2]);

  // ════════════════════════════════════════════════════════════════════
  // RELAY: subscribe to incoming messages
  // ════════════════════════════════════════════════════════════════════

  // Use a ref so the relay handler always calls the LATEST handleRelayBlob
  // without needing to re-subscribe on every state change. Re-subscribing
  // on every collected-array change creates a window where async-decrypted
  // relay messages can be emitted between off() and on(), losing data.
  const handleRelayBlobRef = useRef(handleRelayBlob);
  handleRelayBlobRef.current = handleRelayBlob;

  useEffect(() => {
    if (!relayClient) return;
    const handler = (_from: number, payload: Uint8Array) => {
      const text = new TextDecoder().decode(payload);
      // Intercept barrier messages: "BARRIER:<phase>:<partyId>"
      const m = text.match(/^BARRIER:([\w-]+):(\d+)$/);
      if (m) {
        const phase = m[1]!;
        const pid = parseInt(m[2]!, 10);
        setBarriers(prev => {
          const next = { ...prev };
          const s = new Set(prev[phase]);
          s.add(pid);
          next[phase] = s;
          return next;
        });
        return;
      }
      // Intercept FLINK-COMPLETE from leader
      if (text.startsWith('FLINK-COMPLETE:')) {
        const sigHex = text.slice('FLINK-COMPLETE:'.length);
        dispatch({ type: 'SET_FROST_LINK_SIG', sig: sigHex });
        dispatch({ type: 'SET_STEP', step: 'complete' });
        return;
      }
      handleRelayBlobRef.current(text);
    };
    relayClient.on('message', handler);
    return () => { relayClient.off('message', handler); };
  }, [relayClient]); // stable — only re-subscribe when the client itself changes

  // ── Relay send helpers ──
  const relaySendBlob = useCallback(async (blob: string, to?: number) => {
    if (!relayClientRef.current) return;
    const bytes = new TextEncoder().encode(blob);
    if (to !== undefined) {
      await relayClientRef.current.send(to, bytes);
    } else {
      await relayClientRef.current.broadcast(bytes);
    }
  }, []);

  // ════════════════════════════════════════════════════════════════════
  // STEP: JOIN
  // ════════════════════════════════════════════════════════════════════

  const handleCreateSession = useCallback(() => {
    const sid = generateSessionId();
    const inst = createDKGInstance(state.level, state.threshold, state.parties);
    const setup = inst.dkgSetup(sid);
    dispatch({ type: 'INIT_SESSION', sessionId: sid, instance: inst, bitmasks: setup.bitmasks, holdersOf: setup.holdersOf });
    dispatch({ type: 'SET_PARTY_ID', partyId: 0 }); // Initiator is party 0
  }, [state.level, state.threshold, state.parties]);

  const [joinPaste, setJoinPaste] = useState('');

  const handleJoinSession = useCallback(() => {
    const config = decodeSessionConfig(joinPaste.trim());
    if (!config) {
      dispatch({ type: 'SET_ERROR', error: 'Invalid session config blob' });
      return;
    }
    const sid = sessionIdFromHex(config.sid);
    dispatch({ type: 'SET_PARAMS', threshold: config.t, parties: config.n, level: config.level });
    const inst = createDKGInstance(config.level, config.t, config.n);
    const setup = inst.dkgSetup(sid);
    dispatch({ type: 'INIT_SESSION', sessionId: sid, instance: inst, bitmasks: setup.bitmasks, holdersOf: setup.holdersOf });
    dispatch({ type: 'SET_PARTY_ID', partyId: 1 }); // Default joiner to party 1 (party 0 is initiator)
  }, [joinPaste]);

  const sessionBlob = state.sessionId
    ? encodeSessionConfig(state.threshold, state.parties, state.level, state.sessionId)
    : null;

  // ════════════════════════════════════════════════════════════════════
  // RELAY: Create Session
  // ════════════════════════════════════════════════════════════════════

  const handleRelayCreate = useCallback(async () => {
    setRelayError('');
    setRelayStatus('Connecting...');

    const client = new RelayClient(RELAY_URL);
    relayClientRef.current = client;

    client.on('joined', (_partyId, count, total) => {
      setRelayPartyCount(count);
      setRelayPartyTotal(total);
      setRelayStatus(`Waiting for parties... (${count}/${total})`);
    });

    client.on('ready', (pubkeys) => {
      void (async () => {
        const fp = await sessionFingerprint(pubkeys);
        setRelayFingerprint(fp);
        setRelayReady(true);
        setRelayStatus('All parties connected');

        // Create the DKG session
        const sid = generateSessionId();
        const inst = createDKGInstance(state.level, state.threshold, state.parties);
        const setup = inst.dkgSetup(sid);
        dispatch({ type: 'INIT_SESSION', sessionId: sid, instance: inst, bitmasks: setup.bitmasks, holdersOf: setup.holdersOf });
        dispatch({ type: 'SET_PARTY_ID', partyId: client.partyId });

        // Broadcast the session config to all peers
        const configBlob = encodeSessionConfig(state.threshold, state.parties, state.level, sid);
        const configBytes = new TextEncoder().encode(configBlob);
        await client.broadcast(configBytes);

        // Auto-advance to commit phase
        dispatch({ type: 'SET_STEP', step: 'commit' });
      })();
    });

    client.on('error', (errMsg) => {
      setRelayError(errMsg);
    });

    try {
      // DKG: parties = N (total parties), threshold is the DKG threshold
      const result = await client.create(state.parties, state.threshold);
      setRelaySessionCode(result.session);
      setRelaySessionUrl(result.url);
      setRelayClient(client);
      setRelayStatus(`Session created. Waiting for parties... (1/${state.parties})`);
      setRelayPartyCount(1);
      setRelayPartyTotal(state.parties);
    } catch (err) {
      setRelayError(err instanceof Error ? err.message : 'Failed to create relay session');
      setRelayStatus('');
      client.close();
      relayClientRef.current = null;
    }
  }, [state.level, state.threshold, state.parties]);

  // ════════════════════════════════════════════════════════════════════
  // RELAY: Join Session
  // ════════════════════════════════════════════════════════════════════

  // Ref to track whether we've received the session config (prevents double-init)
  const relayConfigReceived = useRef(false);

  const handleRelayJoin = useCallback(async () => {
    if (!relayJoinCode.trim()) return;
    setRelayError('');
    setRelayStatus('Connecting...');

    const client = new RelayClient(RELAY_URL);
    relayClientRef.current = client;
    relayConfigReceived.current = false;

    // Listen for the session config broadcast from party 0 only
    client.on('message', (from, payload) => {
      if (relayConfigReceived.current) return;
      if (from !== 0) return; // Only accept config from the session creator
      try {
        const text = new TextDecoder().decode(payload);
        const config = decodeSessionConfig(text);
        if (!config) return; // Not a session config — ignore
        relayConfigReceived.current = true;

        const sid = sessionIdFromHex(config.sid);
        dispatch({ type: 'SET_PARAMS', threshold: config.t, parties: config.n, level: config.level });
        const inst = createDKGInstance(config.level, config.t, config.n);
        const setup = inst.dkgSetup(sid);
        dispatch({ type: 'INIT_SESSION', sessionId: sid, instance: inst, bitmasks: setup.bitmasks, holdersOf: setup.holdersOf });
        dispatch({ type: 'SET_PARTY_ID', partyId: client.partyId });

        // Auto-advance to commit phase
        dispatch({ type: 'SET_STEP', step: 'commit' });
      } catch {
        // Not a session config — ignore
      }
    });

    client.on('ready', (pubkeys) => {
      void (async () => {
        const fp = await sessionFingerprint(pubkeys);
        setRelayFingerprint(fp);
        setRelayReady(true);
        setRelayStatus('Connected — waiting for session config from creator...');
      })();
    });

    client.on('error', (errMsg) => {
      setRelayError(errMsg);
    });

    try {
      await client.join(relayJoinCode.trim().toUpperCase());
      setRelaySessionCode(client.sessionCode);
      setRelayClient(client);
      setRelayStatus('Joined session — waiting for all parties...');
    } catch (err) {
      setRelayError(err instanceof Error ? err.message : 'Failed to join relay session');
      setRelayStatus('');
      client.close();
      relayClientRef.current = null;
    }
  }, [relayJoinCode]);

  // ════════════════════════════════════════════════════════════════════
  // STEP: COMMIT (Phase 1)
  // ════════════════════════════════════════════════════════════════════

  const handleGenerateCommitment = useCallback(() => {
    if (!state.instance || !state.sessionId) return;
    try {
      const { broadcast, state: ph1State } = state.instance.dkgPhase1(state.myPartyId, state.sessionId);
      const blob = encodePhase1Broadcast(broadcast, state.sessionId);
      dispatch({ type: 'SET_PHASE1', state: ph1State, blob, ownBroadcast: broadcast });
    } catch (e) {
      dispatch({ type: 'SET_ERROR', error: `Phase 1 failed: ${e instanceof Error ? e.message : String(e)}` });
    }
  }, [state.instance, state.sessionId, state.myPartyId]);

  const phase1Ready = state.collectedPhase1.length === state.parties;

  // Relay: auto-generate commitment once we enter commit phase
  const relayPhase1Generated = useRef(false);
  useEffect(() => {
    if (!isRelayMode || state.step !== 'commit' || relayPhase1Generated.current) return;
    if (!state.instance || !state.sessionId) return;
    relayPhase1Generated.current = true;
    // Small delay to let state settle
    setTimeout(() => {
      handleGenerateCommitment();
    }, 100);
  }, [isRelayMode, state.step, state.instance, state.sessionId, handleGenerateCommitment]);

  // Relay: auto-broadcast Phase 1 blob when generated (await completion)
  const phase1BlobSending = useRef(false);
  useEffect(() => {
    if (!isRelayMode || !state.myPhase1Blob || phase1BlobSending.current || phase1Sent) return;
    phase1BlobSending.current = true;
    void (async () => {
      await relaySendBlob(state.myPhase1Blob!);
      setPhase1Sent(true);
    })();
  }, [isRelayMode, state.myPhase1Blob, phase1Sent, relaySendBlob]);

  // Relay: broadcast barrier when own blob sent + all blobs collected
  useEffect(() => {
    if (!isRelayMode || state.step !== 'commit') return;
    if (phase1Ready && phase1Sent && !barrierSentRef.current.commit) {
      barrierSentRef.current.commit = true;
      void relaySendBlob(`BARRIER:commit:${state.myPartyId}`);
      setBarriers(prev => {
        const s = new Set(prev.commit); s.add(state.myPartyId);
        return { ...prev, commit: s };
      });
    }
  }, [isRelayMode, state.step, phase1Ready, phase1Sent, state.collectedPhase1.length, state.myPartyId, relaySendBlob]);

  // Relay: auto-advance only when ALL parties have confirmed via barrier
  useEffect(() => {
    if (!isRelayMode || state.step !== 'commit') return;
    if ((barriers.commit?.size ?? 0) >= state.parties) {
      dispatch({ type: 'SET_STEP', step: 'reveal' });
    }
  }, [isRelayMode, state.step, barriers, state.parties]);

  // ════════════════════════════════════════════════════════════════════
  // STEP: REVEAL (Phase 2)
  // ════════════════════════════════════════════════════════════════════

  // Refs guard one-shot computations and also prevent StrictMode double-execution.
  // Reset on error so the phase can be retried.
  const phase2Computed = useRef(false);

  useEffect(() => {
    if (state.step !== 'reveal' || phase2Computed.current) return;
    if (!state.instance || !state.sessionId || !state.phase1State) return;
    if (state.collectedPhase1.length !== state.parties) return;
    phase2Computed.current = true;
    try {
      const sorted = [...state.collectedPhase1].sort((a, b) => a.partyId - b.partyId);
      const { broadcast, privateToHolders } = state.instance.dkgPhase2(
        state.myPartyId, state.sessionId, state.phase1State, sorted,
      );
      const pubBlob = encodePhase2Broadcast(broadcast, state.sessionId);
      const privBlobs = new Map<number, string>();
      for (const [targetId, priv] of privateToHolders) {
        privBlobs.set(targetId, encodePhase2Private(priv, targetId, state.sessionId));
      }
      dispatch({ type: 'SET_PHASE2', pubBlob, privBlobs, ownPub: broadcast });
    } catch (e) {
      phase2Computed.current = false;
      dispatch({ type: 'SET_ERROR', error: `Phase 2 failed: ${e instanceof Error ? e.message : String(e)}` });
    }
  }, [state.step, state.instance, state.sessionId, state.phase1State, state.myPartyId, state.collectedPhase1, state.parties]);

  // Relay: auto-send Phase 2 blobs (public broadcast + private to targets, await completion)
  const phase2BlobsSending = useRef(false);
  useEffect(() => {
    if (!isRelayMode || !state.myPhase2PubBlob || phase2BlobsSending.current || phase2Sent) return;
    phase2BlobsSending.current = true;
    void (async () => {
      await relaySendBlob(state.myPhase2PubBlob!);
      for (const [targetId, blob] of state.myPhase2PrivBlobs) {
        await relaySendBlob(blob, targetId);
      }
      setPhase2Sent(true);
    })();
  }, [isRelayMode, state.myPhase2PubBlob, state.myPhase2PrivBlobs, phase2Sent, relaySendBlob]);

  // Count expected private blobs for Phase 2
  const getExpectedPhase2PrivCount = useCallback((): number => {
    const senders = new Set<number>();
    for (const holders of state.holdersOf.values()) {
      if (holders.includes(state.myPartyId)) {
        for (const h of holders) {
          if (h !== state.myPartyId) senders.add(h);
        }
      }
    }
    return senders.size;
  }, [state.holdersOf, state.myPartyId]);

  const phase2PubReady = state.collectedPhase2Pub.length === state.parties;
  const phase2PrivReady = state.collectedPhase2Priv.length >= getExpectedPhase2PrivCount();
  const phase2Ready = phase2PubReady && phase2PrivReady;

  // Relay: broadcast barrier when own blobs sent + all blobs collected
  useEffect(() => {
    if (!isRelayMode || state.step !== 'reveal') return;
    if (phase2Ready && phase2Sent && !barrierSentRef.current.reveal) {
      barrierSentRef.current.reveal = true;
      void relaySendBlob(`BARRIER:reveal:${state.myPartyId}`);
      setBarriers(prev => {
        const s = new Set(prev.reveal); s.add(state.myPartyId);
        return { ...prev, reveal: s };
      });
    }
  }, [isRelayMode, state.step, phase2Ready, phase2Sent, state.collectedPhase2Pub.length, state.collectedPhase2Priv.length, state.myPartyId, relaySendBlob]);

  // Relay: auto-advance only when ALL parties have confirmed via barrier
  useEffect(() => {
    if (!isRelayMode || state.step !== 'reveal') return;
    if ((barriers.reveal?.size ?? 0) >= state.parties) {
      dispatch({ type: 'SET_STEP', step: 'masks' });
    }
  }, [isRelayMode, state.step, barriers, state.parties]);

  // ════════════════════════════════════════════════════════════════════
  // STEP: MASKS (Phase 2 Finalize + Phase 3)
  // ════════════════════════════════════════════════════════════════════

  const phase2FinalComputed = useRef(false);

  useEffect(() => {
    if (state.step !== 'masks' || phase2FinalComputed.current) return;
    if (!state.instance || !state.sessionId || !state.phase1State) return;
    phase2FinalComputed.current = true;
    try {
      const sortedPh1 = [...state.collectedPhase1].sort((a, b) => a.partyId - b.partyId);
      const sortedPh2Pub = [...state.collectedPhase2Pub].sort((a, b) => a.partyId - b.partyId);

      const result = state.instance.dkgPhase2Finalize(
        state.myPartyId, state.sessionId, state.phase1State,
        sortedPh1, sortedPh2Pub, state.collectedPhase2Priv,
      );

      const privBlobs = new Map<number, string>();
      for (const [targetId, priv] of result.privateToAll) {
        privBlobs.set(targetId, encodePhase3Private(priv, targetId, state.sessionId));
      }

      dispatch({ type: 'SET_PHASE2_FINAL', result, privBlobs });
    } catch (e) {
      phase2FinalComputed.current = false;
      dispatch({ type: 'SET_ERROR', error: `Phase 2 Finalize failed: ${e instanceof Error ? e.message : String(e)}` });
    }
  }, [state.step, state.instance, state.sessionId, state.phase1State, state.myPartyId,
      state.collectedPhase1, state.collectedPhase2Pub, state.collectedPhase2Priv]);

  // Relay: auto-send Phase 3 private blobs (await completion)
  const phase3BlobsSending = useRef(false);
  useEffect(() => {
    if (!isRelayMode || !state.phase2FinalResult || state.myPhase3PrivBlobs.size === 0 || phase3BlobsSending.current || phase3Sent) return;
    phase3BlobsSending.current = true;
    void (async () => {
      for (const [targetId, blob] of state.myPhase3PrivBlobs) {
        await relaySendBlob(blob, targetId);
      }
      setPhase3Sent(true);
    })();
  }, [isRelayMode, state.phase2FinalResult, state.myPhase3PrivBlobs, phase3Sent, relaySendBlob]);

  // Count expected Phase 3 private mask blobs
  const getExpectedPhase3PrivCount = useCallback((): number => {
    if (!state.phase2FinalResult) return 0;
    const generators = new Set<number>();
    for (const genId of state.phase2FinalResult.generatorAssignment.values()) {
      if (genId !== state.myPartyId) generators.add(genId);
    }
    return generators.size;
  }, [state.phase2FinalResult, state.myPartyId]);

  const phase3Ready = state.phase2FinalResult !== null &&
    state.collectedPhase3Priv.length >= getExpectedPhase3PrivCount();

  // Relay: broadcast barrier when own blobs sent + all blobs collected
  useEffect(() => {
    if (!isRelayMode || state.step !== 'masks') return;
    if (phase3Ready && phase3Sent && !barrierSentRef.current.masks) {
      barrierSentRef.current.masks = true;
      void relaySendBlob(`BARRIER:masks:${state.myPartyId}`);
      setBarriers(prev => {
        const s = new Set(prev.masks); s.add(state.myPartyId);
        return { ...prev, masks: s };
      });
    }
  }, [isRelayMode, state.step, phase3Ready, phase3Sent, state.collectedPhase3Priv.length, state.myPartyId, relaySendBlob]);

  // Relay: auto-advance only when ALL parties have confirmed via barrier
  useEffect(() => {
    if (!isRelayMode || state.step !== 'masks') return;
    if ((barriers.masks?.size ?? 0) >= state.parties) {
      dispatch({ type: 'SET_STEP', step: 'aggregate' });
    }
  }, [isRelayMode, state.step, barriers, state.parties]);

  // ════════════════════════════════════════════════════════════════════
  // STEP: AGGREGATE (Phase 4)
  // ════════════════════════════════════════════════════════════════════

  const phase4Computed = useRef(false);

  useEffect(() => {
    if (state.step !== 'aggregate' || phase4Computed.current) return;
    if (!state.instance || !state.phase2FinalResult) return;
    phase4Computed.current = true;
    try {
      const broadcast = state.instance.dkgPhase4(
        state.myPartyId,
        state.bitmasks,
        state.phase2FinalResult.generatorAssignment,
        state.collectedPhase3Priv,
        state.phase2FinalResult.ownMaskPieces,
      );
      const blob = encodePhase4Broadcast(broadcast, state.sessionId!);
      dispatch({ type: 'SET_PHASE4', blob, ownBroadcast: broadcast });
    } catch (e) {
      phase4Computed.current = false;
      dispatch({ type: 'SET_ERROR', error: `Phase 4 failed: ${e instanceof Error ? e.message : String(e)}` });
    }
  }, [state.step, state.instance, state.sessionId, state.myPartyId,
      state.bitmasks, state.phase2FinalResult, state.collectedPhase3Priv]);

  // Relay: auto-broadcast Phase 4 blob (await completion)
  const phase4BlobSending = useRef(false);
  useEffect(() => {
    if (!isRelayMode || !state.myPhase4Blob || phase4BlobSending.current || phase4Sent) return;
    phase4BlobSending.current = true;
    void (async () => {
      await relaySendBlob(state.myPhase4Blob!);
      setPhase4Sent(true);
    })();
  }, [isRelayMode, state.myPhase4Blob, phase4Sent, relaySendBlob]);

  const phase4Ready = state.collectedPhase4.length === state.parties;

  // Relay: broadcast barrier when own blob sent + all blobs collected
  useEffect(() => {
    if (!isRelayMode || state.step !== 'aggregate') return;
    if (phase4Ready && phase4Sent && !barrierSentRef.current.aggregate) {
      barrierSentRef.current.aggregate = true;
      void relaySendBlob(`BARRIER:aggregate:${state.myPartyId}`);
      setBarriers(prev => {
        const s = new Set(prev.aggregate); s.add(state.myPartyId);
        return { ...prev, aggregate: s };
      });
    }
  }, [isRelayMode, state.step, phase4Ready, phase4Sent, state.collectedPhase4.length, state.myPartyId, relaySendBlob]);

  // Relay: auto-advance only when ALL parties have confirmed via barrier
  useEffect(() => {
    if (!isRelayMode || state.step !== 'aggregate') return;
    if ((barriers.aggregate?.size ?? 0) >= state.parties) {
      dispatch({ type: 'SET_STEP', step: 'frost-commit' });
    }
  }, [isRelayMode, state.step, barriers, state.parties]);

  // ════════════════════════════════════════════════════════════════════
  // STEP: FROST-COMMIT (FROST DKG Round 1)
  // ════════════════════════════════════════════════════════════════════

  const frostR1Computed = useRef(false);

  useEffect(() => {
    if (state.step !== 'frost-commit' || frostR1Computed.current) return;
    if (!state.sessionId) return;
    frostR1Computed.current = true;
    try {
      const id = partyIdToFrostId(state.myPartyId);
      const rng = { fillBytes: (dest: Uint8Array) => crypto.getRandomValues(dest) };
      const { secretPackage, package: pkg } = frostDkgRound1(id, state.parties, state.threshold, rng);
      const blob = encodeFrostRound1(pkg, state.sessionId);
      dispatch({ type: 'SET_FROST_R1', secret: secretPackage, blob, ownPackage: pkg });
    } catch (e) {
      frostR1Computed.current = false;
      dispatch({ type: 'SET_ERROR', error: `FROST Round 1 failed: ${e instanceof Error ? e.message : String(e)}` });
    }
  }, [state.step, state.sessionId, state.myPartyId, state.parties, state.threshold]);

  // Relay: auto-broadcast FROST R1 blob
  const frostR1BlobSending = useRef(false);
  useEffect(() => {
    if (!isRelayMode || !state.myFrostR1Blob || frostR1BlobSending.current || frostR1Sent) return;
    frostR1BlobSending.current = true;
    void (async () => {
      await relaySendBlob(state.myFrostR1Blob!);
      setFrostR1Sent(true);
    })();
  }, [isRelayMode, state.myFrostR1Blob, frostR1Sent, relaySendBlob]);

  const frostR1Ready = state.collectedFrostR1.length === state.parties;

  // Relay: barrier
  useEffect(() => {
    if (!isRelayMode || state.step !== 'frost-commit') return;
    if (frostR1Ready && frostR1Sent && !barrierSentRef.current['frost-commit']) {
      barrierSentRef.current['frost-commit'] = true;
      void relaySendBlob(`BARRIER:frost-commit:${state.myPartyId}`);
      setBarriers(prev => {
        const s = new Set(prev['frost-commit']); s.add(state.myPartyId);
        return { ...prev, 'frost-commit': s };
      });
    }
  }, [isRelayMode, state.step, frostR1Ready, frostR1Sent, state.collectedFrostR1.length, state.myPartyId, relaySendBlob]);

  // Relay: auto-advance
  useEffect(() => {
    if (!isRelayMode || state.step !== 'frost-commit') return;
    if ((barriers['frost-commit']?.size ?? 0) >= state.parties) {
      dispatch({ type: 'SET_STEP', step: 'frost-shares' });
    }
  }, [isRelayMode, state.step, barriers, state.parties]);

  // ════════════════════════════════════════════════════════════════════
  // STEP: FROST-SHARES (FROST DKG Round 2)
  // ════════════════════════════════════════════════════════════════════

  const frostR2Computed = useRef(false);

  useEffect(() => {
    if (state.step !== 'frost-shares' || frostR2Computed.current) return;
    if (!state.frostR1Secret || !state.sessionId) return;
    if (state.collectedFrostR1.length !== state.parties) return;
    frostR2Computed.current = true;
    try {
      // Build the received map (all parties' Round1Packages, keyed by FROST identifier)
      const received = new Map<bigint, FrostRound1Package>();
      for (const pkg of state.collectedFrostR1) {
        if (pkg.identifier !== partyIdToFrostId(state.myPartyId)) {
          received.set(pkg.identifier, pkg);
        }
      }
      const { secretPackage, packages } = frostDkgRound2(state.frostR1Secret, received);
      const blobs = new Map<number, string>();
      for (const [recipientId, pkg] of packages) {
        const targetPartyId = frostIdToPartyId(recipientId);
        blobs.set(targetPartyId, encodeFrostRound2(pkg, state.sessionId));
      }
      dispatch({ type: 'SET_FROST_R2', secret: secretPackage, blobs });
    } catch (e) {
      frostR2Computed.current = false;
      dispatch({ type: 'SET_ERROR', error: `FROST Round 2 failed: ${e instanceof Error ? e.message : String(e)}` });
    }
  }, [state.step, state.frostR1Secret, state.sessionId, state.myPartyId, state.collectedFrostR1, state.parties]);

  // Relay: auto-send FROST R2 private blobs
  const frostR2BlobsSending = useRef(false);
  useEffect(() => {
    if (!isRelayMode || state.myFrostR2Blobs.size === 0 || frostR2BlobsSending.current || frostR2Sent) return;
    frostR2BlobsSending.current = true;
    void (async () => {
      for (const [targetId, blob] of state.myFrostR2Blobs) {
        await relaySendBlob(blob, targetId);
      }
      setFrostR2Sent(true);
    })();
  }, [isRelayMode, state.myFrostR2Blobs, frostR2Sent, relaySendBlob]);

  // Expected: one Round2Package from each other party
  const frostR2Ready = state.collectedFrostR2.length === state.parties - 1;

  // Relay: barrier
  useEffect(() => {
    if (!isRelayMode || state.step !== 'frost-shares') return;
    if (frostR2Ready && frostR2Sent && !barrierSentRef.current['frost-shares']) {
      barrierSentRef.current['frost-shares'] = true;
      void relaySendBlob(`BARRIER:frost-shares:${state.myPartyId}`);
      setBarriers(prev => {
        const s = new Set(prev['frost-shares']); s.add(state.myPartyId);
        return { ...prev, 'frost-shares': s };
      });
    }
  }, [isRelayMode, state.step, frostR2Ready, frostR2Sent, state.collectedFrostR2.length, state.myPartyId, relaySendBlob]);

  // Relay: auto-advance
  useEffect(() => {
    if (!isRelayMode || state.step !== 'frost-shares') return;
    if ((barriers['frost-shares']?.size ?? 0) >= state.parties) {
      dispatch({ type: 'SET_STEP', step: 'frost-link' });
    }
  }, [isRelayMode, state.step, barriers, state.parties]);

  // ════════════════════════════════════════════════════════════════════
  // STEP: FROST-LINK (FROST-sign the OPNet key-link message)
  // ════════════════════════════════════════════════════════════════════

  // Auto-start: compute key-link hash, run FROST signRound1, broadcast commitment
  useEffect(() => {
    if (state.step !== 'frost-link' || flinkInitRef.current) return;
    if (!state.frostKeyPackage || !state.frostPublicKeyPackage || !state.publicKey) return;
    if (!state.sessionId) return;
    flinkInitRef.current = true;

    const aggKey = state.frostPublicKeyPackage.verifyingKey;
    const untweakedKey = state.frostPublicKeyPackage.untweakedVerifyingKey;

    // Fetch network from config, compute hash, start round 1
    void import('../lib/api').then(({ getConfig }) => getConfig()).then(async cfg => {
      const hash = await computeKeyLinkHash(state.publicKey!, aggKey, untweakedKey, cfg.network);
      flinkHashRef.current = hash;

      const rng = { fillBytes(dest: Uint8Array) { crypto.getRandomValues(dest); } };
      const { nonces, commitments } = frostSignR1(state.frostKeyPackage!, rng);
      flinkNoncesRef.current = nonces;

      // Add own commitment
      flinkCommitmentsRef.current.set(state.myPartyId, commitments);
      setFlinkR1Count(flinkCommitmentsRef.current.size);

      // Broadcast via relay
      if (relayClient) {
        const blob = encodeFrostSignR1(state.myPartyId, [commitments], state.sessionId!);
        void relaySendBlob(blob);
      }
    }).catch(e => {
      dispatch({ type: 'SET_ERROR', error: `Key link failed: ${e instanceof Error ? e.message : String(e)}` });
    });
  }, [state.step, state.frostKeyPackage, state.frostPublicKeyPackage, state.publicKey, state.sessionId, state.myPartyId, relayClient, relaySendBlob]);

  // When all R1 commitments collected: compute R2 (signRound2 with tweaked=true)
  useEffect(() => {
    if (state.step !== 'frost-link' || flinkR2DoneRef.current) return;
    if (flinkR1Count < state.parties || !flinkHashRef.current || !flinkNoncesRef.current || !state.frostKeyPackage || !state.sessionId) return;
    flinkR2DoneRef.current = true;

    try {
      const allCommitments: SigningCommitment[] = [];
      for (const [, c] of flinkCommitmentsRef.current) allCommitments.push(c);

      const share = frostSignR2(
        state.frostKeyPackage,
        flinkNoncesRef.current,
        flinkHashRef.current,
        allCommitments,
        { tweaked: true },
      );

      // Add own share
      flinkSharesRef.current.set(state.myPartyId, share);
      setFlinkR2Count(flinkSharesRef.current.size);

      // Broadcast
      if (relayClient) {
        const blob = encodeFrostSignR2(state.myPartyId, [share], state.sessionId);
        void relaySendBlob(blob);
      }
    } catch (e) {
      dispatch({ type: 'SET_ERROR', error: `Key link R2 failed: ${e instanceof Error ? e.message : String(e)}` });
    }
  }, [state.step, flinkR1Count, state.parties, state.frostKeyPackage, state.sessionId, relayClient, relaySendBlob]);

  // When all R2 shares collected: aggregate and advance to complete
  useEffect(() => {
    if (state.step !== 'frost-link') return;
    if (flinkR2Count < state.parties || !flinkHashRef.current || !state.frostKeyPackage) return;

    try {
      const allCommitments: SigningCommitment[] = [];
      for (const [, c] of flinkCommitmentsRef.current) allCommitments.push(c);

      const allShares: SignatureShare[] = [];
      for (const [, s] of flinkSharesRef.current) allShares.push(s);

      const pubKeyPkg: FrostPublicKeyPackage = {
        verifyingKey: state.frostKeyPackage.verifyingKey,
        untweakedVerifyingKey: state.frostKeyPackage.untweakedVerifyingKey,
        verifyingShares: new Map(),
        untweakedVerifyingShares: new Map(),
        minSigners: state.threshold,
      };

      const sig = frostSignAgg(allShares, flinkHashRef.current, allCommitments, pubKeyPkg, { tweaked: true });
      const sigHex = toHex(sig);
      dispatch({ type: 'SET_FROST_LINK_SIG', sig: sigHex });

      // Broadcast result to other parties
      if (relayClient) {
        void relaySendBlob(`FLINK-COMPLETE:${sigHex}`);
      }

      dispatch({ type: 'SET_STEP', step: 'complete' });
    } catch (e) {
      dispatch({ type: 'SET_ERROR', error: `Key link aggregate failed: ${e instanceof Error ? e.message : String(e)}` });
    }
  }, [state.step, flinkR2Count, state.parties, state.frostKeyPackage, state.threshold, relayClient, relaySendBlob]);

  // ════════════════════════════════════════════════════════════════════
  // FINALIZE: runs at frost-link entry (moved from complete step)
  // ════════════════════════════════════════════════════════════════════

  const finalizeComputed = useRef(false);

  useEffect(() => {
    if (state.step !== 'frost-link' || finalizeComputed.current) return;
    if (!state.instance || !state.phase2FinalResult) return;
    if (!state.frostR2Secret) return;
    finalizeComputed.current = true;
    try {
      // ML-DSA finalize
      const sortedPh4 = [...state.collectedPhase4].sort((a, b) => a.partyId - b.partyId);
      const { publicKey, share } = state.instance.dkgFinalize(
        state.myPartyId,
        state.phase2FinalResult.rho,
        sortedPh4,
        state.phase2FinalResult.shares,
      );
      dispatch({ type: 'SET_RESULT', publicKey, share });

      // FROST finalize
      const receivedR1 = new Map<bigint, FrostRound1Package>();
      for (const pkg of state.collectedFrostR1) {
        if (pkg.identifier !== partyIdToFrostId(state.myPartyId)) {
          receivedR1.set(pkg.identifier, pkg);
        }
      }
      const receivedR2 = new Map<bigint, FrostRound2Package>();
      for (const pkg of state.collectedFrostR2) {
        receivedR2.set(pkg.sender, pkg);
      }
      const { keyPackage, publicKeyPackage } = frostDkgFinalize(state.frostR2Secret, receivedR1, receivedR2);
      dispatch({ type: 'SET_FROST_RESULT', keyPackage, publicKeyPackage });
    } catch (e) {
      finalizeComputed.current = false;
      dispatch({ type: 'SET_ERROR', error: `Finalize failed: ${e instanceof Error ? e.message : String(e)}` });
    }
  }, [state.step, state.instance, state.myPartyId, state.phase2FinalResult, state.collectedPhase4,
      state.frostR2Secret, state.collectedFrostR1, state.collectedFrostR2]);

  // ── Download handler ──
  const handleDownload = useCallback(async (password: string) => {
    if (!state.share || !state.publicKey || !state.frostKeyPackage || !state.frostPublicKeyPackage) return;
    try {
      const { K, L } = getKL(state.level);
      const shareFile = await encryptShareV3(
        state.share,
        state.frostKeyPackage,
        toHex(state.publicKey),
        toHex(state.frostPublicKeyPackage.verifyingKey),
        state.threshold,
        state.parties,
        state.level,
        K, L,
        password,
      );
      downloadShareFile(shareFile);
      // Save DKG result to backend config
      try {
        const { saveDKG } = await import('../lib/api');
        await saveDKG({
          threshold: state.threshold,
          parties: state.parties,
          level: state.level,
          combinedPubKey: toHex(state.publicKey),
          shareData: shareFile.encrypted,
          frostAggregateKey: toHex(state.frostPublicKeyPackage!.verifyingKey),
          frostUntweakedAggregateKey: toHex(state.frostPublicKeyPackage!.untweakedVerifyingKey),
          frostLegacySig: state.frostLinkSig ?? undefined,
        });
        onComplete?.();
      } catch (e) {
        console.error('Failed to save DKG to config:', e);
        // Don't block — the share file was already downloaded
        onComplete?.();
      }
      setShowPasswordModal(false);
    } catch (e) {
      dispatch({ type: 'SET_ERROR', error: `Encryption failed: ${e instanceof Error ? e.message : String(e)}` });
      setShowPasswordModal(false);
    }
  }, [state.share, state.publicKey, state.frostKeyPackage, state.frostPublicKeyPackage, state.level, state.threshold, state.parties, state.frostLinkSig, onComplete]);

  // ── Render ──

  return (
    <div className="ceremony">
      <div style={{ textAlign: 'center', marginBottom: 8 }}>
        <OtziWordmark height={44} />
      </div>
      <h1 style={{ textAlign: 'center', fontSize: 18, fontWeight: 500, marginBottom: 0 }}>DKG Ceremony</h1>
      <p className="subtitle">
        {state.step === 'join'
          ? 'Distributed threshold key generation (ML-DSA + FROST)'
          : `Distributed ${state.threshold}-of-${state.parties} threshold key generation`}
      </p>

      {/* Step dots */}
      <div className="steps">
        {STEP_LABELS.map((_, i) => (
          <div
            key={i}
            className={`step-dot ${i === stepIndex ? 'active' : ''} ${i < stepIndex ? 'done' : ''}`}
          />
        ))}
      </div>

      {/* Do not refresh warning */}
      {stepIndex > 0 && stepIndex < STEPS.length - 1 && (
        <div className="warning">
          Do not refresh this page — all ceremony state is held in memory.
        </div>
      )}

      {/* Error display */}
      {state.error && (
        <div className="warning" style={{ marginBottom: 16 }}>{state.error}</div>
      )}

      {/* ═══════ MODE SELECTOR (before join) ═══════ */}
      {state.step === 'join' && transportMode === 'choose' && (
        <div className="card">
          <h2>Start Ceremony</h2>
          <p>Choose how parties will communicate during the DKG ceremony.</p>

          <div className="form-row" style={{ marginBottom: 16 }}>
            <label>
              Session Code
              <input
                type="text"
                autoFocus
                placeholder="Paste session code to join"
                maxLength={6}
                value={relayJoinCode}
                onChange={e => {
                  const val = e.target.value.toUpperCase().replace(/[^A-Z0-9]/g, '');
                  setRelayJoinCode(val);
                  setRelayError('');
                  if (val.length >= 6) {
                    setTransportMode('relay-join');
                  }
                }}
                style={{ fontFamily: 'monospace', fontSize: 18, letterSpacing: '0.15em', textTransform: 'uppercase', textAlign: 'center' }}
              />
            </label>
          </div>

          <div style={{ fontSize: 12, fontWeight: 600, color: 'var(--white-dim)', marginBottom: 8, textTransform: 'uppercase', letterSpacing: '0.05em' }}>
            Or start a new session
          </div>
          <button
            className="btn btn-primary btn-full"
            style={{ marginBottom: 16 }}
            onClick={() => setTransportMode('relay-create')}
          >
            Create Session
          </button>

          <div style={{ fontSize: 12, fontWeight: 600, color: 'var(--white-dim)', marginBottom: 8, textTransform: 'uppercase', letterSpacing: '0.05em' }}>
            Offline (Manual)
          </div>
          <button
            className="btn btn-secondary btn-full"
            onClick={() => setTransportMode('offline')}
          >
            Offline Mode
          </button>
          <p style={{ fontSize: 13, color: 'var(--white-dim)', marginTop: 8 }}>
            Copy and paste blobs manually between parties.
          </p>
        </div>
      )}

      {/* ═══════ RELAY-CREATE: setup ═══════ */}
      {state.step === 'join' && transportMode === 'relay-create' && (
        <div className="card">
          <h2>Create Relay Session</h2>

          {!relaySessionCode && (
            <>
              <div className="form-row">
                <label>
                  Threshold (T)
                  <select
                    value={state.threshold}
                    onChange={e => {
                      const t = Number(e.target.value);
                      dispatch({ type: 'SET_PARAMS', threshold: t, parties: Math.max(t, state.parties), level: state.level });
                    }}
                  >
                    {[2, 3, 4, 5].map(n => <option key={n} value={n}>{n}</option>)}
                  </select>
                </label>
                <label>
                  Parties (N)
                  <select
                    value={state.parties}
                    onChange={e => dispatch({ type: 'SET_PARAMS', threshold: state.threshold, parties: Number(e.target.value), level: state.level })}
                  >
                    {[2, 3, 4, 5, 6].filter(n => n >= state.threshold).map(n => (
                      <option key={n} value={n}>{n}</option>
                    ))}
                  </select>
                </label>
              </div>

              <button
                className="btn btn-primary btn-full"
                style={{ marginTop: 16 }}
                onClick={() => void handleRelayCreate()}
              >
                Create Session
              </button>
            </>
          )}

          {/* Session created — waiting for parties */}
          {relaySessionCode && !relayReady && (() => {
            // Build join URL from hosting config (runtime state)
            const h = hostingConfig;
            const joinUrl = h?.domain
              ? `${h.httpsEnabled ? 'https' : 'http'}://${h.domain}${h.port && h.port !== 443 && h.port !== 80 ? `:${h.port}` : ''}${h.path || ''}?session=${relaySessionCode}`
              : relaySessionUrl || null;
            return (
            <div style={{ marginTop: 16 }}>
              <div style={{ marginBottom: 12 }}>
                <span style={{ fontSize: 12, color: 'var(--white-dim)' }}>Session Code</span>
                <div
                  style={{ fontFamily: 'monospace', fontSize: 20, fontWeight: 700, letterSpacing: '0.15em', cursor: 'pointer' }}
                  onClick={() => navigator.clipboard.writeText(joinUrl || relaySessionCode)}
                  title="Click to copy"
                >
                  {relaySessionCode}
                </div>
              </div>
              {joinUrl && (
                <div style={{ marginBottom: 12 }}>
                  <div
                    style={{ fontFamily: 'monospace', fontSize: 12, wordBreak: 'break-all', color: 'var(--accent)', cursor: 'pointer' }}
                    onClick={() => navigator.clipboard.writeText(joinUrl)}
                    title="Click to copy link"
                  >
                    {joinUrl}
                  </div>
                </div>
              )}
              <p style={{ fontSize: 13, color: 'var(--white-dim)' }}>
                Share this {joinUrl ? 'link' : 'code'} with {state.parties - 1} other parties.
              </p>
              <div style={{ textAlign: 'center', padding: 12 }}>
                <div className="spinner" style={{ margin: '0 auto 8px' }} />
                <p style={{ fontSize: 14 }}>{relayStatus || `Waiting for parties... (${relayPartyCount}/${relayPartyTotal})`}</p>
              </div>
            </div>
            );
          })()}

          {/* Ready — show fingerprint */}
          {relayReady && relayFingerprint && (
            <div style={{ marginTop: 16 }}>
              <div style={{ marginBottom: 12 }}>
                <span style={{ fontSize: 12, color: 'var(--white-dim)' }}>Session Fingerprint</span>
                <div style={{ fontFamily: 'monospace', fontSize: 16, fontWeight: 600 }}>{relayFingerprint}</div>
              </div>
              <div className="success-box">
                {relayStatus || 'All parties connected — starting ceremony...'}
              </div>
            </div>
          )}

          {relayError && (
            <div className="warning" style={{ marginTop: 12 }}>{relayError}</div>
          )}

          <button
            className="btn btn-secondary btn-full"
            style={{ marginTop: 16 }}
            onClick={() => {
              if (relayClientRef.current) {
                relayClientRef.current.close();
                relayClientRef.current = null;
              }
              setRelayClient(null);
              setRelaySessionCode('');
              setRelaySessionUrl('');
              setRelayReady(false);
              setRelayFingerprint('');
              setRelayStatus('');
              setRelayError('');
              setTransportMode('choose');
            }}
          >
            Back
          </button>
        </div>
      )}

      {/* ═══════ RELAY-JOIN: enter code ═══════ */}
      {state.step === 'join' && transportMode === 'relay-join' && (
        <div className="card">
          <h2>Join Relay Session</h2>

          {!relayClient && (
            <>
              <p style={{ fontSize: 13, color: 'var(--white-dim)' }}>
                Enter the 6-character session code from the session creator.
              </p>
              <div className="form-row">
                <label>
                  Session Code
                  <input
                    type="text"
                    placeholder="e.g. X7K2M9"
                    maxLength={6}
                    value={relayJoinCode}
                    onChange={e => { setRelayJoinCode(e.target.value.toUpperCase()); setRelayError(''); }}
                    style={{ fontFamily: 'monospace', fontSize: 18, letterSpacing: '0.15em', textTransform: 'uppercase', textAlign: 'center' }}
                  />
                </label>
              </div>
              <button
                className="btn btn-primary btn-full"
                style={{ marginTop: 8 }}
                disabled={relayJoinCode.trim().length < 6}
                onClick={() => void handleRelayJoin()}
              >
                Join
              </button>
            </>
          )}

          {/* Joined — waiting for ready */}
          {relayClient && !relayReady && (
            <div style={{ marginTop: 16 }}>
              <div style={{ marginBottom: 12 }}>
                <span style={{ fontSize: 12, color: 'var(--white-dim)' }}>Session Code</span>
                <div style={{ fontFamily: 'monospace', fontSize: 20, fontWeight: 700, letterSpacing: '0.15em' }}>
                  {relaySessionCode}
                </div>
              </div>
              <div style={{ textAlign: 'center', padding: 12 }}>
                <div className="spinner" style={{ margin: '0 auto 8px' }} />
                <p style={{ fontSize: 14 }}>{relayStatus || 'Waiting for all parties...'}</p>
              </div>
            </div>
          )}

          {/* Ready — waiting for session config */}
          {relayReady && relayFingerprint && state.step === 'join' && (
            <div style={{ marginTop: 16 }}>
              <div style={{ marginBottom: 12 }}>
                <span style={{ fontSize: 12, color: 'var(--white-dim)' }}>Session Fingerprint</span>
                <div style={{ fontFamily: 'monospace', fontSize: 16, fontWeight: 600 }}>{relayFingerprint}</div>
                <p style={{ fontSize: 12, color: 'var(--white-dim)', marginTop: 4 }}>
                  Verify this matches what the session creator sees.
                </p>
              </div>
              <div style={{ textAlign: 'center', padding: 12 }}>
                <div className="spinner" style={{ margin: '0 auto 8px' }} />
                <p style={{ fontSize: 14 }}>Connected — waiting for session config from creator...</p>
              </div>
            </div>
          )}

          {relayError && (
            <div className="warning" style={{ marginTop: 12 }}>{relayError}</div>
          )}

          <button
            className="btn btn-secondary btn-full"
            style={{ marginTop: 16 }}
            onClick={() => {
              if (relayClientRef.current) {
                relayClientRef.current.close();
                relayClientRef.current = null;
              }
              setRelayClient(null);
              setRelaySessionCode('');
              setRelayReady(false);
              setRelayFingerprint('');
              setRelayStatus('');
              setRelayError('');
              setRelayJoinCode('');
              setTransportMode('choose');
            }}
          >
            Back
          </button>
        </div>
      )}

      {/* ═══════ STEP: JOIN (offline mode) ═══════ */}
      {state.step === 'join' && transportMode === 'offline' && (
        <div className="card">
          <h2>Join Ceremony</h2>

          {/* Role selector */}
          <div className="form-row" style={{ marginBottom: 24 }}>
            <label>
              Role
              <select
                value={state.role}
                onChange={e => dispatch({ type: 'SET_ROLE', role: e.target.value as Role })}
              >
                <option value="initiator">Initiator (create new session)</option>
                <option value="joiner">Joiner (paste session config)</option>
              </select>
            </label>
          </div>

          {state.role === 'initiator' && (
            <>
              <div className="form-row">
                <label>
                  Threshold (T)
                  <select
                    value={state.threshold}
                    onChange={e => {
                      const t = Number(e.target.value);
                      dispatch({ type: 'SET_PARAMS', threshold: t, parties: Math.max(t, state.parties), level: state.level });
                    }}
                  >
                    {[2, 3, 4, 5].map(n => <option key={n} value={n}>{n}</option>)}
                  </select>
                </label>
                <label>
                  Parties (N)
                  <select
                    value={state.parties}
                    onChange={e => dispatch({ type: 'SET_PARAMS', threshold: state.threshold, parties: Number(e.target.value), level: state.level })}
                  >
                    {[2, 3, 4, 5, 6].filter(n => n >= state.threshold).map(n => (
                      <option key={n} value={n}>{n}</option>
                    ))}
                  </select>
                </label>
              </div>
              <p>
                Dealerless DKG: no single party generates or sees all key material.
                Each party runs this page independently.
              </p>
              {!state.sessionId && (
                <button className="btn btn-primary btn-full" onClick={handleCreateSession}>
                  Create Session
                </button>
              )}
              {state.sessionId && sessionBlob && (
                <>
                  <BlobOutput blob={sessionBlob} label="Session Config" onCopy={copyToClipboard} copiedLabel={copied} />
                  <p style={{ fontSize: 13, color: 'var(--white-dim)' }}>
                    Share this blob with all {state.parties - 1} other parties.
                    You are Party 1 (index 0).
                  </p>
                  <button
                    className="btn btn-primary btn-full"
                    onClick={() => dispatch({ type: 'SET_STEP', step: 'commit' })}
                  >
                    Continue to Commit Phase
                  </button>
                </>
              )}
            </>
          )}

          {state.role === 'joiner' && (
            <>
              <textarea
                className="blob-textarea"
                placeholder="Paste the session config blob from the initiator..."
                value={joinPaste}
                onChange={e => setJoinPaste(e.target.value)}
                rows={3}
              />
              {!state.sessionId && (
                <button
                  className="btn btn-secondary btn-full"
                  style={{ marginTop: 8 }}
                  onClick={handleJoinSession}
                  disabled={!joinPaste.trim()}
                >
                  Load Session
                </button>
              )}
              {state.sessionId && (
                <>
                  <div className="success-box" style={{ marginTop: 12 }}>
                    Session loaded: {state.threshold}-of-{state.parties}, ML-DSA-{state.level}
                  </div>
                  <div className="form-row">
                    <label>
                      I am Party
                      <select
                        value={state.myPartyId}
                        onChange={e => dispatch({ type: 'SET_PARTY_ID', partyId: Number(e.target.value) })}
                      >
                        {Array.from({ length: state.parties }, (_, i) => i)
                          .filter(i => i !== 0)
                          .map(i => (
                            <option key={i} value={i}>Party {i + 1}</option>
                          ))}
                      </select>
                    </label>
                  </div>
                  <p style={{ fontSize: 12, color: 'var(--white-dim)' }}>
                    Coordinate with other parties to ensure each selects a unique party number.
                  </p>
                  <button
                    className="btn btn-primary btn-full"
                    onClick={() => dispatch({ type: 'SET_STEP', step: 'commit' })}
                  >
                    Continue to Commit Phase
                  </button>
                </>
              )}
            </>
          )}

          <button
            className="btn btn-secondary btn-full"
            style={{ marginTop: 16 }}
            onClick={() => setTransportMode('choose')}
          >
            Back
          </button>
        </div>
      )}

      {/* ═══════ STEP: COMMIT (Phase 1) ═══════ */}
      {state.step === 'commit' && (
        <div className="card">
          <h2>Phase 1: Commit</h2>
          {isRelayMode ? (
            <p>Generating and exchanging commitments via relay...</p>
          ) : (
            <p>Generate your cryptographic commitment and share it with all parties.</p>
          )}

          {!state.myPhase1Blob && !isRelayMode && (
            <button className="btn btn-primary btn-full" onClick={handleGenerateCommitment}>
              Generate Commitment
            </button>
          )}

          {/* Relay mode: progress indicator */}
          {isRelayMode && (
            <>
              <PartyTracker
                collected={state.collectedPhase1.map(b => b.partyId)}
                total={state.parties}
                myPartyId={state.myPartyId}
                label="Commitments"
              />
              {!phase1Ready && (
                <RelayPhaseProgress
                  phase="Phase 1"
                  collected={state.collectedPhase1.length}
                  total={state.parties}
                  label="commitments received"
                />
              )}
            </>
          )}

          {/* Offline mode: full blob exchange UI */}
          {state.myPhase1Blob && !isRelayMode && (
            <>
              <BlobOutput blob={state.myPhase1Blob} label="My Phase 1 Commitment" onCopy={copyToClipboard} copiedLabel={copied} />
              <PartyTracker
                collected={state.collectedPhase1.map(b => b.partyId)}
                total={state.parties}
                myPartyId={state.myPartyId}
                label="Commitments"
              />
              <PasteArea value={pasteValue} onChange={setPasteValue} onProcess={handlePaste} />
              <button
                className="btn btn-primary btn-full"
                style={{ marginTop: 16 }}
                onClick={() => dispatch({ type: 'SET_STEP', step: 'reveal' })}
                disabled={!phase1Ready}
              >
                {phase1Ready
                  ? 'Continue to Reveal Phase'
                  : `Waiting for ${state.parties - state.collectedPhase1.length} more commitment(s)`}
              </button>
            </>
          )}
        </div>
      )}

      {/* ═══════ STEP: REVEAL (Phase 2) ═══════ */}
      {state.step === 'reveal' && (
        <div className="card">
          <h2>Phase 2: Reveal</h2>
          {isRelayMode ? (
            <p>Exchanging reveals via relay...</p>
          ) : (
            <p>Share your public reveal with everyone, and private reveals with specified parties.</p>
          )}

          {!state.myPhase2PubBlob && (
            <div style={{ textAlign: 'center', padding: 20 }}>
              <div className="spinner" style={{ margin: '0 auto 12px' }} />
              <p>Computing Phase 2...</p>
            </div>
          )}

          {state.myPhase2PubBlob && isRelayMode && (
            <>
              <PartyTracker
                collected={state.collectedPhase2Pub.map(b => b.partyId)}
                total={state.parties}
                myPartyId={state.myPartyId}
                label="Public reveals"
              />
              <div className="party-tracker" style={{ marginTop: 4 }}>
                <span className="tracker-label">Private reveals: {state.collectedPhase2Priv.length}/{getExpectedPhase2PrivCount()}</span>
              </div>
              {!phase2Ready && (
                <RelayPhaseProgress
                  phase="Phase 2"
                  collected={state.collectedPhase2Pub.length + state.collectedPhase2Priv.length}
                  total={state.parties + getExpectedPhase2PrivCount()}
                  label="blobs received"
                />
              )}
            </>
          )}

          {state.myPhase2PubBlob && !isRelayMode && (
            <>
              <BlobOutput blob={state.myPhase2PubBlob} label="Public Reveal (send to everyone)" onCopy={copyToClipboard} copiedLabel={copied} />

              {[...state.myPhase2PrivBlobs.entries()].map(([targetId, blob]) => (
                <BlobOutput
                  key={targetId}
                  blob={blob}
                  label={`Private for Party ${targetId + 1}`}
                  isPrivate
                  targetParty={targetId}
                  onCopy={copyToClipboard}
                  copiedLabel={copied}
                />
              ))}

              <PartyTracker
                collected={state.collectedPhase2Pub.map(b => b.partyId)}
                total={state.parties}
                myPartyId={state.myPartyId}
                label="Public reveals"
              />
              <div className="party-tracker" style={{ marginTop: 4 }}>
                <span className="tracker-label">Private reveals: {state.collectedPhase2Priv.length}/{getExpectedPhase2PrivCount()}</span>
              </div>

              <PasteArea value={pasteValue} onChange={setPasteValue} onProcess={handlePaste} />

              <button
                className="btn btn-primary btn-full"
                style={{ marginTop: 16 }}
                onClick={() => dispatch({ type: 'SET_STEP', step: 'masks' })}
                disabled={!phase2Ready}
              >
                {phase2Ready
                  ? 'Continue to Masks Phase'
                  : 'Waiting for more reveals...'}
              </button>
            </>
          )}
        </div>
      )}

      {/* ═══════ STEP: MASKS (Phase 2 Finalize + Phase 3) ═══════ */}
      {state.step === 'masks' && (
        <div className="card">
          <h2>Phase 3: Masks</h2>
          {isRelayMode ? (
            <p>Exchanging mask blobs via relay...</p>
          ) : (
            <p>Mask generation and distribution. Some parties generate masks for specific bitmask groups.</p>
          )}

          {!state.phase2FinalResult && (
            <div style={{ textAlign: 'center', padding: 20 }}>
              <div className="spinner" style={{ margin: '0 auto 12px' }} />
              <p>Computing masks...</p>
            </div>
          )}

          {state.phase2FinalResult && isRelayMode && (
            <>
              <div className="party-tracker" style={{ marginTop: 12 }}>
                <span className="tracker-label">
                  Received masks: {state.collectedPhase3Priv.length}/{getExpectedPhase3PrivCount()}
                </span>
              </div>
              {!phase3Ready && getExpectedPhase3PrivCount() > 0 && (
                <RelayPhaseProgress
                  phase="Phase 3"
                  collected={state.collectedPhase3Priv.length}
                  total={getExpectedPhase3PrivCount()}
                  label="mask blobs received"
                />
              )}
              {getExpectedPhase3PrivCount() === 0 && state.myPhase3PrivBlobs.size === 0 && (
                <div className="success-box">
                  No mask exchange needed for your party in this round.
                </div>
              )}
            </>
          )}

          {state.phase2FinalResult && !isRelayMode && (
            <>
              {/* Generator assignments */}
              <div className="generator-info">
                <strong>Generator assignments:</strong>
                {[...state.phase2FinalResult.generatorAssignment.entries()].slice(0, 8).map(([bitmask, genId]) => (
                  <div key={bitmask} style={{ fontSize: 12, color: 'var(--white-dim)' }}>
                    Bitmask {bitmask.toString(2).padStart(state.parties, '0')}: Party {genId + 1}
                    {genId === state.myPartyId ? ' (you)' : ''}
                  </div>
                ))}
                {state.phase2FinalResult.generatorAssignment.size > 8 && (
                  <div style={{ fontSize: 12, color: 'var(--white-dim)' }}>
                    ...and {state.phase2FinalResult.generatorAssignment.size - 8} more
                  </div>
                )}
              </div>

              {/* Private mask blobs to distribute */}
              {state.myPhase3PrivBlobs.size > 0 && (
                <>
                  <p style={{ marginTop: 16 }}>
                    You are a generator for some bitmasks. Send these private blobs:
                  </p>
                  {[...state.myPhase3PrivBlobs.entries()].map(([targetId, blob]) => (
                    <BlobOutput
                      key={targetId}
                      blob={blob}
                      label={`Masks for Party ${targetId + 1}`}
                      isPrivate
                      targetParty={targetId}
                      onCopy={copyToClipboard}
                      copiedLabel={copied}
                    />
                  ))}
                </>
              )}

              {state.myPhase3PrivBlobs.size === 0 && getExpectedPhase3PrivCount() === 0 && (
                <div className="success-box">
                  No mask exchange needed for your party in this round.
                </div>
              )}

              {getExpectedPhase3PrivCount() > 0 && (
                <>
                  <div className="party-tracker" style={{ marginTop: 12 }}>
                    <span className="tracker-label">
                      Received masks: {state.collectedPhase3Priv.length}/{getExpectedPhase3PrivCount()}
                    </span>
                  </div>
                  <PasteArea value={pasteValue} onChange={setPasteValue} onProcess={handlePaste} />
                </>
              )}

              <button
                className="btn btn-primary btn-full"
                style={{ marginTop: 16 }}
                onClick={() => dispatch({ type: 'SET_STEP', step: 'aggregate' })}
                disabled={!phase3Ready}
              >
                {phase3Ready
                  ? 'Continue to Aggregate Phase'
                  : 'Waiting for mask blobs...'}
              </button>
            </>
          )}
        </div>
      )}

      {/* ═══════ STEP: AGGREGATE (Phase 4) ═══════ */}
      {state.step === 'aggregate' && (
        <div className="card">
          <h2>Phase 4: Aggregate</h2>
          {isRelayMode ? (
            <p>Exchanging aggregates via relay...</p>
          ) : (
            <p>Each party broadcasts their aggregate. Collect all to derive the shared public key.</p>
          )}

          {!state.myPhase4Blob && (
            <div style={{ textAlign: 'center', padding: 20 }}>
              <div className="spinner" style={{ margin: '0 auto 12px' }} />
              <p>Computing aggregate...</p>
            </div>
          )}

          {state.myPhase4Blob && isRelayMode && (
            <>
              <PartyTracker
                collected={state.collectedPhase4.map(b => b.partyId)}
                total={state.parties}
                myPartyId={state.myPartyId}
                label="Aggregates"
              />
              {!phase4Ready && (
                <RelayPhaseProgress
                  phase="Phase 4"
                  collected={state.collectedPhase4.length}
                  total={state.parties}
                  label="aggregates received"
                />
              )}
            </>
          )}

          {state.myPhase4Blob && !isRelayMode && (
            <>
              <BlobOutput blob={state.myPhase4Blob} label="My Aggregate (send to everyone)" onCopy={copyToClipboard} copiedLabel={copied} />

              <PartyTracker
                collected={state.collectedPhase4.map(b => b.partyId)}
                total={state.parties}
                myPartyId={state.myPartyId}
                label="Aggregates"
              />

              <PasteArea value={pasteValue} onChange={setPasteValue} onProcess={handlePaste} />

              <button
                className="btn btn-primary btn-full"
                style={{ marginTop: 16 }}
                onClick={() => dispatch({ type: 'SET_STEP', step: 'frost-commit' })}
                disabled={!phase4Ready}
              >
                {phase4Ready
                  ? 'Continue to FROST Key Generation'
                  : `Waiting for ${state.parties - state.collectedPhase4.length} more aggregate(s)`}
              </button>
            </>
          )}
        </div>
      )}

      {/* ═══════ STEP: FROST-COMMIT (FROST DKG Round 1) ═══════ */}
      {state.step === 'frost-commit' && (
        <div className="card">
          <h2>FROST Round 1: Commitments</h2>
          {isRelayMode ? (
            <p>Generating and exchanging FROST key commitments via relay...</p>
          ) : (
            <p>Each party generates FROST key material and broadcasts their commitment.</p>
          )}

          {!state.myFrostR1Blob && (
            <div style={{ textAlign: 'center', padding: 20 }}>
              <div className="spinner" style={{ margin: '0 auto 12px' }} />
              <p>Computing FROST Round 1...</p>
            </div>
          )}

          {state.myFrostR1Blob && isRelayMode && (
            <>
              <PartyTracker
                collected={state.collectedFrostR1.map(p => frostIdToPartyId(p.identifier))}
                total={state.parties}
                myPartyId={state.myPartyId}
                label="FROST Commitments"
              />
              {!frostR1Ready && (
                <RelayPhaseProgress
                  phase="FROST R1"
                  collected={state.collectedFrostR1.length}
                  total={state.parties}
                  label="commitments received"
                />
              )}
            </>
          )}

          {state.myFrostR1Blob && !isRelayMode && (
            <>
              <BlobOutput blob={state.myFrostR1Blob} label="My FROST Commitment (send to everyone)" onCopy={copyToClipboard} copiedLabel={copied} />
              <PartyTracker
                collected={state.collectedFrostR1.map(p => frostIdToPartyId(p.identifier))}
                total={state.parties}
                myPartyId={state.myPartyId}
                label="FROST Commitments"
              />
              <PasteArea value={pasteValue} onChange={setPasteValue} onProcess={handlePaste} />
              <button
                className="btn btn-primary btn-full"
                style={{ marginTop: 16 }}
                onClick={() => dispatch({ type: 'SET_STEP', step: 'frost-shares' })}
                disabled={!frostR1Ready}
              >
                {frostR1Ready
                  ? 'Continue to FROST Share Distribution'
                  : `Waiting for ${state.parties - state.collectedFrostR1.length} more commitment(s)`}
              </button>
            </>
          )}
        </div>
      )}

      {/* ═══════ STEP: FROST-SHARES (FROST DKG Round 2) ═══════ */}
      {state.step === 'frost-shares' && (
        <div className="card">
          <h2>FROST Round 2: Share Distribution</h2>
          {isRelayMode ? (
            <p>Exchanging FROST secret shares via relay...</p>
          ) : (
            <p>Send each party their private FROST share. These are secret — share only with the named recipient.</p>
          )}

          {state.myFrostR2Blobs.size === 0 && (
            <div style={{ textAlign: 'center', padding: 20 }}>
              <div className="spinner" style={{ margin: '0 auto 12px' }} />
              <p>Computing FROST Round 2...</p>
            </div>
          )}

          {state.myFrostR2Blobs.size > 0 && isRelayMode && (
            <>
              <PartyTracker
                collected={state.collectedFrostR2.map(p => frostIdToPartyId(p.sender))}
                total={state.parties}
                myPartyId={state.myPartyId}
                label="FROST Shares"
              />
              {!frostR2Ready && (
                <RelayPhaseProgress
                  phase="FROST R2"
                  collected={state.collectedFrostR2.length}
                  total={state.parties - 1}
                  label="shares received"
                />
              )}
            </>
          )}

          {state.myFrostR2Blobs.size > 0 && !isRelayMode && (
            <>
              {[...state.myFrostR2Blobs.entries()].map(([targetId, blob]) => (
                <BlobOutput
                  key={targetId}
                  blob={blob}
                  label={`FROST Share for Party ${targetId + 1}`}
                  isPrivate
                  targetParty={targetId}
                  onCopy={copyToClipboard}
                  copiedLabel={copied}
                />
              ))}
              <PartyTracker
                collected={state.collectedFrostR2.map(p => frostIdToPartyId(p.sender))}
                total={state.parties}
                myPartyId={state.myPartyId}
                label="FROST Shares"
              />
              <PasteArea value={pasteValue} onChange={setPasteValue} onProcess={handlePaste} />
              <button
                className="btn btn-primary btn-full"
                style={{ marginTop: 16 }}
                onClick={() => dispatch({ type: 'SET_STEP', step: 'frost-link' })}
                disabled={!frostR2Ready}
              >
                {frostR2Ready
                  ? 'Key Link'
                  : `Waiting for ${state.parties - 1 - state.collectedFrostR2.length} more share(s)`}
              </button>
            </>
          )}
        </div>
      )}

      {/* ═══════ STEP: FROST-LINK (Key Link Signing) ═══════ */}
      {state.step === 'frost-link' && (
        <div className="card">
          <h2>Key Link</h2>
          <div className="threshold-hint" style={{ textAlign: 'center', padding: '16px 0' }}>
            Signing OPNet key link...
            {flinkR1Count < state.parties
              ? ` (commitments: ${flinkR1Count}/${state.parties})`
              : flinkR2Count < state.parties
              ? ` (shares: ${flinkR2Count}/${state.parties})`
              : ' aggregating...'}
          </div>
          {state.error && <div className="step-status error">{state.error}</div>}
        </div>
      )}

      {/* ═══════ STEP: COMPLETE ═══════ */}
      {state.step === 'complete' && (
        <div className="card">
          <h2>Ceremony Complete</h2>

          {(!state.publicKey || !state.frostKeyPackage) && (
            <div style={{ textAlign: 'center', padding: 20 }}>
              <div className="spinner" style={{ margin: '0 auto 12px' }} />
              <p>Finalizing key derivation...</p>
            </div>
          )}

          {state.publicKey && state.share && state.frostKeyPackage && state.frostPublicKeyPackage && (
            <>
              <div className="success-box">
                Unified DKG complete. Both ML-DSA (post-quantum contract signing) and
                FROST (threshold BTC wallet) keys generated. No single party ever had
                access to the full secret keys.
              </div>

              {isRelayMode && relayFingerprint && (
                <div style={{ marginBottom: 16 }}>
                  <span style={{ fontSize: 12, color: 'var(--white-dim)' }}>Session Fingerprint</span>
                  <div style={{ fontFamily: 'monospace', fontSize: 14, fontWeight: 600 }}>{relayFingerprint}</div>
                </div>
              )}

              <h3 style={{ fontSize: 15, fontWeight: 600, marginBottom: 8 }}>ML-DSA Public Key</h3>
              <div className="pubkey-display">{toHex(state.publicKey)}</div>
              <button
                className="btn btn-secondary btn-full"
                style={{ marginBottom: 16 }}
                onClick={() => copyToClipboard(toHex(state.publicKey!), 'pubkey')}
              >
                {copied === 'pubkey' ? 'Copied!' : 'Copy ML-DSA Public Key'}
              </button>

              <h3 style={{ fontSize: 15, fontWeight: 600, marginBottom: 8 }}>FROST Aggregate Public Key</h3>
              <div className="pubkey-display">{toHex(state.frostPublicKeyPackage.verifyingKey)}</div>
              <button
                className="btn btn-secondary btn-full"
                style={{ marginBottom: 16 }}
                onClick={() => copyToClipboard(toHex(state.frostPublicKeyPackage!.verifyingKey), 'frost-pubkey')}
              >
                {copied === 'frost-pubkey' ? 'Copied!' : 'Copy FROST Public Key'}
              </button>

              <button
                className="btn btn-primary btn-full"
                onClick={() => setShowPasswordModal(true)}
              >
                Download Share File (Party {state.myPartyId + 1})
              </button>

              <div style={{ marginTop: 24 }}>
                <p><strong>Next steps:</strong></p>
                <ol style={{ color: 'var(--white-dim)', fontSize: 14, paddingLeft: 20 }}>
                  <li style={{ marginBottom: 8 }}>
                    Each party downloads and securely stores their share file
                  </li>
                  <li style={{ marginBottom: 8 }}>
                    Verify all parties derived the same public key
                  </li>
                  <li>
                    Use the public key and share files with your threshold signing application
                  </li>
                </ol>
              </div>
            </>
          )}
        </div>
      )}

      {/* Password modal */}
      {showPasswordModal && (
        <PasswordModal
          partyId={state.myPartyId}
          onConfirm={handleDownload}
          onCancel={() => setShowPasswordModal(false)}
        />
      )}
    </div>
  );
}
